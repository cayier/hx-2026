import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import Console


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        threshold = patch.dict("os.environ", {"HX_THRESHOLD": "70"})
        threshold.start()
        self.addCleanup(threshold.stop)
        self.console = Console(Path(directory.name) / "test.db")
        self.console.add_asset(dict(address="demo", name="认证服务", owner="operator-1", criticality=15))
        self.console.add_knowledge(dict(title="认证手册", kind="运维手册", keywords="登录,认证", body="复核日志"))
        self.alert = dict(id="test-1", address="demo", title="登录失败", source="IDS",
                          severity="高危", description="连续失败", initial="疑似异常认证")

    def test_ingest_retains_result_and_deduplicates(self):
        response = self.console.ingest(self.alert)
        self.assertEqual(response["score"], 85)
        self.assertEqual(response["state"], "已完成")
        self.assertEqual(response["notification"], "模拟已发送")
        self.assertEqual(response["result"]["references"][0]["title"], "认证手册")
        with patch.object(self.console, "process") as process:
            self.assertEqual(self.console.ingest(self.alert), response)
            process.assert_not_called()
        with self.assertRaises(ValueError):
            self.console.ingest(self.alert | {"title": "不同内容"})

    def test_low_score_skips_triage(self):
        response = self.console.ingest(self.alert | {"severity": "低危"})
        self.assertEqual(response["state"], "低于阈值")
        self.assertIsNone(response["result"])

    def test_notification_retry_reuses_result(self):
        with patch.object(self.console, "notify", side_effect=OSError):
            response = self.console.ingest(self.alert)
        self.assertEqual(response["state"], "通知失败")
        with patch.object(self.console, "analyze") as analyze:
            self.assertTrue(self.console.process(self.alert["id"]))
            analyze.assert_not_called()
        self.assertEqual(self.console.list("alerts")[0]["state"], "已完成")

    def test_unmatched_asset_can_be_assigned_after_ingestion(self):
        response = self.console.ingest(self.alert | {"address": "unknown"})
        self.assertEqual(response["state"], "待分派")
        self.console.add_asset(dict(address="unknown", name="业务应用", owner="operator-2", criticality=0))
        self.assertTrue(self.console.process(self.alert["id"]))
        record = self.console.list("alerts")[0]
        self.assertEqual(record["owner"], "operator-2")
        self.assertEqual(record["state"], "已完成")

    def test_invalid_model_response_and_retry(self):
        self.console.demo = False
        with patch.dict("os.environ", {"HX_MODEL_URL": "https://model.invalid", "HX_NOTIFY_URL": "https://notify.invalid"}):
            with patch("app.post_https", return_value={"summary": "缺少建议"}):
                response = self.console.ingest(self.alert)
            self.assertEqual(response["state"], "研判失败")
            with patch("app.post_https", side_effect=[
                {"summary": "需复核", "recommendation": "查看日志"}, {"accepted": True},
            ]) as adapter:
                self.assertTrue(self.console.process(self.alert["id"]))
            self.assertEqual(adapter.call_args_list[0].args[1]["references"][0]["body"], "复核日志")
            self.assertEqual(adapter.call_args_list[1].args[1]["recipient"], "operator-1")
        self.assertEqual(self.console.list("alerts")[0]["notification"], "已受理")
