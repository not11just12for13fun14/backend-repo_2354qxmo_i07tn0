import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import Event, Alert

app = FastAPI(title="Insider Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Insider Threat Detection Backend Running"}


class IngestResponse(BaseModel):
    inserted_ids: List[str]


@app.post("/api/events/ingest", response_model=IngestResponse)
async def ingest_events(events: List[Event]):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    inserted: List[str] = []
    for ev in events:
        doc_id = create_document("event", ev)
        inserted.append(doc_id)
    return {"inserted_ids": inserted}


@app.get("/api/events")
async def list_events(
    user: Optional[str] = None,
    source: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    since_minutes: int = Query(60 * 24, ge=1, le=60 * 24 * 30),
    limit: int = Query(200, ge=1, le=2000),
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

    docs = get_documents("event", filter_q, limit)
    # Convert datetimes to isoformat for frontend
    for d in docs:
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].isoformat()
        d["_id"] = str(d.get("_id"))
    return {"items": docs}


# Simple rule engine using stored events; no simulated data. It evaluates existing data.
@app.get("/api/alerts/run", response_model=List[Alert])
async def run_detections(
    window_minutes: int = Query(60 * 24, ge=5, le=60 * 24 * 7),
    threshold_failed_logins: int = Query(5, ge=2, le=50),
    threshold_large_downloads_mb: int = Query(500, ge=100, le=50000),
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
    # Expect events with metadata.size_mb numeric
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

    # Rule 3: Access outside business hours (8am-6pm) to sensitive resources
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

    return alerts


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
