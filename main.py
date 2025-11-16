import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import Event, Alert
import io
import csv

app = FastAPI(title="Insider Threat Detection API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ----------------------------
# Security (simple API key)
# ----------------------------
API_KEY = os.getenv("API_KEY")


def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY:
        if not x_api_key or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True


# ----------------------------
# Startup: create indexes
# ----------------------------
@app.on_event("startup")
def ensure_indexes():
    if db is None:
        return
    try:
        db.event.create_index("timestamp")
        db.event.create_index("user")
        db.event.create_index("action")
        db.event.create_index("status")
        db.event.create_index("source")
        db.alert.create_index([("rule_id", 1), ("user", 1)])
        db.alert.create_index("last_seen")
    except Exception:
        pass


@app.get("/")
def read_root():
    return {"message": "Insider Threat Detection Backend Running"}


class IngestResponse(BaseModel):
    inserted_ids: List[str]


# ----------------------------
# Ingest Events (bulk)
# ----------------------------
@app.post("/api/events/ingest", response_model=IngestResponse, dependencies=[Depends(verify_api_key)])
async def ingest_events(events: List[Event]):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    if not events:
        return {"inserted_ids": []}

    if len(events) > 10000:
        raise HTTPException(status_code=413, detail="Too many events in one request (max 10,000)")

    # Bulk insert for performance
    docs = []
    for ev in events:
        d = ev.model_dump()
        now = datetime.utcnow()
        d["created_at"] = now
        d["updated_at"] = now
        docs.append(d)

    result = db["event"].insert_many(docs)
    inserted = [str(_id) for _id in result.inserted_ids]
    return {"inserted_ids": inserted}


# ----------------------------
# List Events with filters + pagination
# ----------------------------
@app.get("/api/events", dependencies=[Depends(verify_api_key)])
async def list_events(
    user: Optional[str] = None,
    source: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    earliest = datetime.utcnow() - timedelta(minutes=since_minutes)
    filter_q: Dict[str, Any] = {"timestamp": {"$gte": earliest}}
    if user:
        filter_q["user"] = user
    if source:
        filter_q["source"] = source
    if action:
        filter_q["action"] = action
    if status:
        filter_q["status"] = status

    total = db.event.count_documents(filter_q)
    skip = (page - 1) * page_size
    cursor = db.event.find(filter_q).sort("timestamp", -1).skip(skip).limit(page_size)
    docs = list(cursor)

    for d in docs:
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        d["_id"] = str(d.get("_id"))

    return {"items": docs, "page": page, "page_size": page_size, "total": total}


# ----------------------------
# Detection engine
# ----------------------------
@app.get("/api/alerts/run", response_model=List[Alert], dependencies=[Depends(verify_api_key)])
async def run_detections(
    window_minutes: int = Query(60 * 24, ge=5, le=60 * 24 * 7),
    threshold_failed_logins: int = Query(5, ge=2, le=50),
    threshold_large_downloads_mb: int = Query(500, ge=100, le=50000),
    persist: bool = Query(False, description="Persist generated alerts to the database"),
):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    start_time = datetime.utcnow() - timedelta(minutes=window_minutes)

    alerts: List[Alert] = []

    # Rule 1: Excessive failed logins by user
    failed_cursor = db.event.aggregate([
        {"$match": {"timestamp": {"$gte": start_time}, "action": "login", "status": {"$in": ["failed", "denied"]}}},
        {"$group": {"_id": "$user", "count": {"$sum": 1}, "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}}},
        {"$match": {"count": {"$gte": threshold_failed_logins}}},
    ])
    for doc in failed_cursor:
        user = doc.get("_id") or "unknown"
        alert = Alert(
            rule_id="R1_failed_login_surge",
            severity="medium",
            title=f"Excessive failed logins for {user}",
            description=f"Detected {doc['count']} failed/denied logins in the last {window_minutes} minutes.",
            user=user,
            first_seen=doc["first"],
            last_seen=doc["last"],
            count=doc["count"],
            context={},
        )
        alerts.append(alert)

    # Rule 2: Large data transfer/download events
    download_cursor = db.event.aggregate([
        {"$match": {"timestamp": {"$gte": start_time}, "action": {"$in": ["download", "exfiltrate", "transfer"]}}},
        {"$project": {"user": 1, "timestamp": 1, "size_mb": {"$toDouble": "$metadata.size_mb"}}},
        {"$match": {"size_mb": {"$gte": float(threshold_large_downloads_mb)}}},
        {"$group": {"_id": "$user", "count": {"$sum": 1}, "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}, "total_mb": {"$sum": "$size_mb"}}},
    ])
    for doc in download_cursor:
        user = doc.get("_id") or "unknown"
        alert = Alert(
            rule_id="R2_large_transfers",
            severity="high",
            title=f"Large data transfers by {user}",
            description=f"{doc['count']} events totaling {int(doc.get('total_mb', 0))} MB.",
            user=user,
            first_seen=doc["first"],
            last_seen=doc["last"],
            count=doc["count"],
            context={"total_mb": doc.get("total_mb", 0)},
        )
        alerts.append(alert)

    # Rule 3: After-hours access to sensitive resources
    sensitive_cursor = db.event.aggregate([
        {"$match": {"timestamp": {"$gte": start_time}, "action": {"$in": ["read", "write", "download"]}, "resource": {"$regex": r"/sensitive|/confidential|/restricted", "$options": "i"}}},
        {"$addFields": {"hour": {"$hour": "$timestamp"}}},
        {"$match": {"$or": [{"hour": {"$lt": 8}}, {"hour": {"$gt": 18}}]}},
        {"$group": {"_id": "$user", "count": {"$sum": 1}, "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}}},
    ])
    for doc in sensitive_cursor:
        user = doc.get("_id") or "unknown"
        alert = Alert(
            rule_id="R3_after_hours_sensitive_access",
            severity="medium",
            title=f"After-hours access to sensitive data by {user}",
            description=f"{doc['count']} events outside business hours.",
            user=user,
            first_seen=doc["first"],
            last_seen=doc["last"],
            count=doc["count"],
            context={},
        )
        alerts.append(alert)

    # Sort by severity/count
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    alerts.sort(key=lambda a: (sev_order.get(a.severity, 0), a.count), reverse=True)

    if persist:
        for a in alerts:
            create_document("alert", a)

    return alerts


# ----------------------------
# Persisted alerts: list + acknowledge
# ----------------------------
class AckRequest(BaseModel):
    ids: List[str]


@app.get("/api/alerts", dependencies=[Depends(verify_api_key)])
async def list_alerts(user: Optional[str] = None, rule_id: Optional[str] = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=1000)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    filt: Dict[str, Any] = {}
    if user:
        filt["user"] = user
    if rule_id:
        filt["rule_id"] = rule_id
    total = db.alert.count_documents(filt)
    skip = (page - 1) * page_size
    items = list(db.alert.find(filt).sort("last_seen", -1).skip(skip).limit(page_size))
    for d in items:
        d["_id"] = str(d["_id"])
        for k in ["first_seen", "last_seen"]:
            if isinstance(d.get(k), datetime):
                d[k] = d[k].isoformat()
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@app.post("/api/alerts/ack", dependencies=[Depends(verify_api_key)])
async def acknowledge_alerts(req: AckRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    from bson import ObjectId
    acked = 0
    for sid in req.ids:
        try:
            db.alert.update_one({"_id": ObjectId(sid)}, {"$set": {"acknowledged": True, "ack_time": datetime.utcnow()}})
            acked += 1
        except Exception:
            pass
    return {"acknowledged": acked}


# ----------------------------
# CSV export of events
# ----------------------------
@app.get("/api/export/events.csv", dependencies=[Depends(verify_api_key)])
async def export_events_csv(
    user: Optional[str] = None,
    source: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30),
):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    earliest = datetime.utcnow() - timedelta(minutes=since_minutes)
    filt: Dict[str, Any] = {"timestamp": {"$gte": earliest}}
    if user:
        filt["user"] = user
    if source:
        filt["source"] = source
    if action:
        filt["action"] = action
    if status:
        filt["status"] = status

    cursor = db.event.find(filt).sort("timestamp", -1)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "user", "action", "status", "resource", "source", "ip", "device"])
    for e in cursor:
        ts = e.get("timestamp")
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        writer.writerow([
            ts,
            e.get("user", ""),
            e.get("action", ""),
            e.get("status", ""),
            e.get("resource", ""),
            e.get("source", ""),
            e.get("ip", ""),
            e.get("device", ""),
        ])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=events.csv"})


# ----------------------------
# Health/Readiness checks
# ----------------------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    ready = db is not None
    return {"status": "ready" if ready else "not_ready"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
