from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel
import time, threading, requests
from .. import state

router = APIRouter()


class SimulateRequest(BaseModel):
    device_id: str
    server_url: str = "http://127.0.0.1:8000"
    demo: bool = True


def _send_telemetry_loop(device_id, server_url):
    """
    Simple demo sequence: 1) Normal (30s), 2) Suspicious (30s), 3) Attack (45s)
    Posts telemetry to the local telemetry ingestion endpoint to simulate a phone.
    """
    logger = __import__('logging').getLogger('dome')
    try:
        url = server_url.rstrip('/') + '/telemetry/ingest'
        # Register the device in state for UI
        now = time.time()
        dev_id = device_id
        state.devices[dev_id] = {
            'device_id': dev_id,
            'ip': '127.0.0.1',
            'hostname': dev_id,
            'status': 'OK',
            'last_seen': now,
            'last_risk': 0,
            'quarantined': False,
            'source': 'simulate'
        }

        def post(payload):
            try:
                requests.post(url, json=payload, timeout=3)
            except Exception as e:
                # log and continue (avoid silent failures during demo)
                try:
                    logger.exception('Simulation post failed: %s', e)
                except Exception:
                    pass

        # Normal (30s)
        end = time.time() + 30
        while time.time() < end:
            payload = {
                'device_id': dev_id,
                'failed_logins': 0,
                'connections': 2,
                'outbound_ips': ['8.8.8.8'],
                'bytes_out': 2000,
                'extra': {'mode': 'normal'},
                'ts': time.time()
            }
            post(payload)
            time.sleep(5)

        # Suspicious (30s)
        end = time.time() + 30
        while time.time() < end:
            payload = {
                'device_id': dev_id,
                'failed_logins': 2,
                'connections': 12,
                'outbound_ips': ['185.220.101.45'],
                'bytes_out': 500000,
                'extra': {'mode': 'suspicious'},
                'ts': time.time()
            }
            post(payload)
            time.sleep(5)

        # Attack (45s)
        end = time.time() + 45
        while time.time() < end:
            payload = {
                'device_id': dev_id,
                'failed_logins': 8,
                'connections': 30,
                'outbound_ips': ['185.220.101.45', '103.145.45.12'],
                'suspicious_file': '/system/app/malware.apk',
                'bytes_out': 6_000_000,
                'extra': {'mode': 'attack'},
                'ts': time.time()
            }
            post(payload)
            time.sleep(5)
    except Exception as e:
        try:
            logger.exception('Simulation loop failed for %s: %s', device_id, e)
        except Exception:
            pass


from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError


@router.post("/simulate")
async def simulate_device(request: Request, background_tasks: BackgroundTasks):
    """
    Start a background simulated device that posts telemetry.
    This handler logs the raw request body and returns clearer validation errors if present.
    """
    logger = __import__('logging').getLogger('dome')
    try:
        raw = await request.body()
        try:
            data = await request.json()
        except Exception:
            data = None
        logger.debug('Simulate request raw body: %s', raw)

        # Validate payload against Pydantic model
        try:
            req = SimulateRequest.model_validate(data or {})
        except ValidationError as ve:
            # In Pydantic v2 ValidationError may still implement .errors(); keep compatibility
            try:
                details = ve.errors()
            except Exception:
                details = str(ve)
            logger.warning('Simulation request validation failed: %s', details)
            return JSONResponse(status_code=422, content={"success": False, "error": "validation_error", "details": details})

        # Start the background simulation thread
        thread = threading.Thread(target=_send_telemetry_loop, args=(req.device_id, req.server_url), daemon=True)
        thread.start()
        logger.info('Simulation started for %s', req.device_id)
        return {"success": True, "message": f"Simulation started for {req.device_id}"}

    except Exception as e:
        try:
            logger.exception('simulate_device error: %s', e)
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})
