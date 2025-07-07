"""
Alert Polling Service - Linux version
Nhận dữ liệu từ server bằng polling, thực thi action (kill process), hiển thị cảnh báo notify-send
"""

import asyncio
import logging
import time
import subprocess
from datetime import datetime
from typing import Dict, Optional, Any
from dataclasses import dataclass

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .communication import ServerCommunication

logger = logging.getLogger('alert_polling')

@dataclass
class AlertPollingStats:
    polls_performed: int = 0
    alerts_received: int = 0
    alerts_displayed: int = 0
    actions_executed: int = 0
    last_poll_time: Optional[datetime] = None
    last_alert_time: Optional[datetime] = None
    consecutive_failures: int = 0
    total_polling_time: float = 0.0

class AlertPollingService:
    def __init__(self, communication: 'ServerCommunication', config_manager=None):
        self.communication = communication
        self.config_manager = config_manager
        self.agent_id = None
        self.polling_interval = 2  # seconds
        self.max_consecutive_failures = 5
        self.is_running = False
        self.is_paused = False
        self.stats = AlertPollingStats()
        self.recent_alerts = {}
        self.alert_cooldown = 60  # seconds
        self.agent_start_time = datetime.now()
        self.logger = logging.getLogger(__name__)
        logger.info("📡 Alert Polling Service (Linux) initialized")

    def set_agent_id(self, agent_id: str):
        self.agent_id = agent_id
        logger.info(f"🎯 Alert Polling Service - Agent ID set: {agent_id}")

    async def start(self):
        if self.is_running:
            logger.warning("⚠️ Alert Polling Service already running")
            return
        self.is_running = True
        self.is_paused = False
        logger.info("🚀 Starting Alert Polling Service (Linux)")
        asyncio.create_task(self._polling_loop())

    async def stop(self):
        self.is_running = False
        logger.info("🛑 Alert Polling Service stopped")

    async def pause(self):
        self.is_paused = True
        logger.info("⏸️ Alert Polling Service paused")

    async def resume(self):
        self.is_paused = False
        logger.info("▶️ Alert Polling Service resumed")

    async def _polling_loop(self):
        while self.is_running:
            try:
                if not self.is_paused and self.agent_id:
                    await self._poll_alerts()
                await asyncio.sleep(self.polling_interval)
            except Exception as e:
                logger.error(f"❌ Polling loop error: {e}")
                self.stats.consecutive_failures += 1
                if self.stats.consecutive_failures >= self.max_consecutive_failures:
                    logger.warning(f"⚠️ Too many consecutive failures ({self.stats.consecutive_failures}), increasing polling interval")
                    await asyncio.sleep(self.polling_interval * 2)
                else:
                    await asyncio.sleep(self.polling_interval)

    async def _poll_alerts(self):
        start_time = time.time()
        try:
            if not self.communication or not self.communication.is_online():
                logger.debug("📡 Server not online, skipping poll")
                return
            if not self.agent_id:
                logger.debug("📡 Agent ID not set, skipping poll")
                return
            alerts = await self.communication._fetch_alerts()
            if alerts:
                self.stats.alerts_received += len(alerts)
                self.stats.last_alert_time = datetime.now()
                logger.info(f"📥 Polled {len(alerts)} alerts from server")
                logger.debug(f"📋 Alerts data: {alerts}")
                for alert_data in alerts:
                    logger.debug(f"📋 Processing alert: {alert_data.get('notification_id', 'unknown')} - {alert_data.get('title', 'Unknown')}")
                    await self._process_alert(alert_data)
            else:
                logger.debug("📭 No pending alerts from server")
            self.stats.consecutive_failures = 0
            self.stats.polls_performed += 1
            self.stats.last_poll_time = datetime.now()
        except Exception as e:
            logger.error(f"❌ Polling failed: {e}")
            self.stats.consecutive_failures += 1
        finally:
            self.stats.total_polling_time += time.time() - start_time

    async def _process_alert(self, alert_data: Dict[str, Any]):
        try:
            alert_time_str = alert_data.get('first_detected') or alert_data.get('timestamp')
            alert_time = None
            if alert_time_str:
                try:
                    alert_time = datetime.fromisoformat(alert_time_str)
                except Exception:
                    alert_time = None
            if alert_time and alert_time < self.agent_start_time:
                logger.debug(f"⏩ Alert {alert_data.get('notification_id')} is old (before agent start), skipping")
                return
            alert_id = alert_data.get('notification_id')
            if alert_id and self._is_alert_in_cooldown(alert_id):
                logger.debug(f"⏰ Alert {alert_id} in cooldown, skipping")
                return
            await self._handle_alert_notification(alert_data)
            if alert_id:
                self.recent_alerts[alert_id] = time.time()
        except Exception as e:
            logger.error(f"❌ Failed to process alert: {e}")

    async def _handle_alert_notification(self, alert_data: Dict[str, Any]):
        try:
            # Hiển thị cảnh báo bằng notify-send (nếu có GUI)
            title = alert_data.get('title', 'Security Alert')
            description = alert_data.get('description', 'Rule violation detected')
            severity = alert_data.get('severity', 'Medium')
            message = f"[{severity}] {title}: {description}"
            await self._show_notification(message)
            # Thực thi action nếu có
            action = alert_data.get('action')
            if action:
                await self._execute_action(action)
        except Exception as e:
            logger.error(f"❌ Failed to handle alert notification: {e}")

    async def _show_notification(self, message: str):
        try:
            # Sử dụng notify-send (chỉ hoạt động trên Linux có GUI)
            cmd = ["notify-send", "EDR Agent", message]
            logger.info(f"🔔 Showing notification: {message}")
            subprocess.run(cmd, check=False)
        except Exception as e:
            logger.warning(f"⚠️ Failed to show notification: {e}")

    async def _execute_action(self, action: Dict[str, Any]) -> bool:
        try:
            action_type = action.get('action_type')
            if action_type == 'kill_process':
                return await self._execute_kill_process(action)
            # Có thể mở rộng thêm các action khác (block_network, quarantine_file, ...)
            else:
                logger.warning(f"⚠️ Unknown action type: {action_type}")
                return False
        except Exception as e:
            logger.error(f"❌ Action execution failed: {e}")
            return False

    async def _execute_kill_process(self, action: Dict[str, Any]) -> bool:
        try:
            pid = action.get('process_id') or action.get('target_pid')
            process_name = action.get('process_name', 'Unknown')
            if not pid:
                logger.error("❌ No PID provided for kill_process")
                await self._show_notification("No PID provided for kill_process")
                return False
            cmd = ["kill", "-9", str(pid)]
            logger.info(f"[AGENT] Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                message = f"Đã kill process {process_name} (PID: {pid}) bằng kill -9"
                logger.info(f"✅ {message}")
                await self._show_notification(message)
                return True
            else:
                error_message = f"Không thể kill process {process_name} (PID: {pid}): {result.stderr}"
                logger.error(f"❌ {error_message}")
                await self._show_notification(error_message)
                return False
        except Exception as e:
            error_message = f"Không thể kill process {process_name} (PID: {pid}): {e}"
            logger.error(f"❌ {error_message}")
            await self._show_notification(error_message)
            return False

    def _is_alert_in_cooldown(self, alert_id: str) -> bool:
        if alert_id not in self.recent_alerts:
            return False
        time_since = time.time() - self.recent_alerts[alert_id]
        return time_since < self.alert_cooldown

    def get_stats(self) -> Dict[str, Any]:
        try:
            total_time = max(self.stats.total_polling_time, 0.001)
            total_polls = max(self.stats.polls_performed, 1)
            return {
                'polls_performed': self.stats.polls_performed,
                'alerts_received': self.stats.alerts_received,
                'alerts_displayed': self.stats.alerts_displayed,
                'actions_executed': self.stats.actions_executed,
                'consecutive_failures': self.stats.consecutive_failures,
                'last_poll_time': self.stats.last_poll_time.isoformat() if self.stats.last_poll_time else None,
                'last_alert_time': self.stats.last_alert_time.isoformat() if self.stats.last_alert_time else None,
                'average_polling_time_ms': round((total_time / total_polls) * 1000, 2),
                'success_rate': round(
                    ((total_polls - self.stats.consecutive_failures) / total_polls) * 100, 2
                ),
                'is_running': self.is_running,
                'is_paused': self.is_paused,
                'polling_interval': self.polling_interval
            }
        except Exception as e:
            logger.error(f"Stats calculation failed: {e}")
            return {
                'polls_performed': 0,
                'alerts_received': 0,
                'alerts_displayed': 0,
                'actions_executed': 0,
                'is_running': self.is_running,
                'is_paused': self.is_paused
            } 