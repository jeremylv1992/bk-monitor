# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
Copyright (C) 2017-2021 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import copy
import time
from enum import Enum
from typing import Dict, List, Tuple

from bkmonitor.views import serializers
from constants.alert import EventStatus
from core.drf_resource import api, resource
from core.drf_resource.base import Resource
from fta_web.alert.handlers.alert import AlertQueryHandler
from monitor_web.models.collecting import CollectConfigMeta
from monitor_web.models.plugin import PluginVersionHistory
from monitor_web.strategies.loader.datalink_loader import get_datalink_strategy_ids


class DataLinkStage(Enum):
    COLLECTING = "collecting"
    TRANSFER = "transfer"
    STORAGE = "storage"


class BaseStatusResource(Resource):
    def __init__(self):
        super().__init__()
        self.collect_config_id: int = None
        self.collect_config: CollectConfigMeta = None
        self.stage: str = None
        self._init = False

    def init_data(self, collect_config_id: str, stage: DataLinkStage = None):
        self.collect_config_id = collect_config_id
        self.collect_config: CollectConfigMeta = CollectConfigMeta.objects.get(id=self.collect_config_id)
        self.stage = stage
        self.strategy_ids = get_datalink_strategy_ids(
            self.collect_config.bk_biz_id, self.collect_config_id, self.stage.value
        )
        self._init = True

    def get_alert_strategies(self) -> Tuple[List[int], List[Dict]]:
        """检索告警配置"""
        strategies = [
            resource.strategies.get_strategy_v2(bk_biz_id=self.collect_config.bk_biz_id, id=sid)
            for sid in self.strategy_ids
        ]
        return strategies

    def search_alert_histogram(self, time_range: int = 3600) -> List[List]:
        start_time, end_time = int(time.time() - time_range), int(time.time())
        request_data = {
            "bk_biz_ids": [self.collect_config.bk_biz_id],
            "query_string": " OR ".join(f"stategy_id : {sid}" for sid in self.strategy_ids),
            "start_time": start_time,
            "end_time": end_time,
        }
        handler = AlertQueryHandler(**request_data)
        series = handler.date_histogram()["series"]
        abnormal_series = [s for s in series if s["name"] == EventStatus.ABNORMAL][0]
        return abnormal_series["data"]

    def get_metrics_json(self) -> List[Dict]:
        """查询采集插件配置的指标维度信息"""
        metric_json = copy.deepcopy(self.collect_config.deployment_config.metrics)
        plugin = self.collect_config.plugin
        # 如果插件id在time_series_group能查到，则可以认为是分表的，否则走原有逻辑
        group_list = api.metadata.query_time_series_group(
            time_series_group_name=f"{plugin.plugin_type}_{plugin.plugin_id}"
        )
        for table in metric_json:
            # 分表模式下，这里table_id都为__default__
            table["table_name"] = table["table_name"] if not group_list else "__default__"
            table["table_id"] = self.get_result_table_id(table["table_name"])
            metric_names: List[str] = list()
            for field in table["fields"]:
                if not field["is_active"]:
                    continue
                if field["monitor_type"] != "metric":
                    continue
                metric_names.append(field["name"])
            table["metric_names"] = metric_names
        return metric_json

    def get_result_table_id(self, table_name: str) -> str:
        """通过采集插件配置，拼接最终 RT_ID"""
        return PluginVersionHistory.get_result_table_id(self.collect_config.plugin, table_name).lower()


class AlertStatusResource(BaseStatusResource):
    """查询数据链路各个阶段的告警状态"""

    class RequestSerilizer(serializers.Serializer):
        collect_config_id = serializers.IntegerField(required=True, label="采集配置ID")
        stage = serializers.ChoiceField(
            required=True, label="告警阶段", choices=[stage.value for stage in list(DataLinkStage)]
        )

    def perform_request(self, validated_request_data: Dict) -> Dict:
        self.init_data(validated_request_data["collect_config_id"], DataLinkStage(validated_request_data["stage"]))
        strategies = self.get_alert_strategies()
        alert_histogram = self.search_alert_histogram()
        return {
            "has_alert": alert_histogram[-1][1],
            "alert_histogram": alert_histogram,
            "alert_config": {
                "user_group_list": strategies[0]["notice"]["user_group_list"] if len(strategies) > 0 else [],
                "strategies": [
                    {
                        "name": strategy["name"],
                        "description": strategy["name"],
                        "id": strategy["id"],
                    }
                    for strategy in strategies
                ],
            },
        }


class CollectingTargetStatusResource(BaseStatusResource):
    class RequestSerilizer(serializers.Serializer):
        collect_config_id = serializers.IntegerField(required=True, label="采集配置ID")

    def perform_request(self, validated_request_data: Dict) -> Dict:
        self.init_data(validated_request_data["collect_config_id"], DataLinkStage.COLLECTING)

        instance_status = resource.collecting.collect_instance_status(id=self.collect_config_id)
        # 提取关联的所有主机ID
        bk_host_ids = []
        for group in instance_status["contents"]:
            for child in group["child"]:
                bk_host_ids.append(child["bk_host_id"])

        alert_histogram = self.search_target_alert_histogram(bk_host_ids)
        targets_alert_histogram = alert_histogram["targets"]

        # 填充主机的告警信息
        for group in instance_status["contents"]:
            for child in group["child"]:
                child["alert_histogram"] = targets_alert_histogram[child["bk_host_id"]]
        return instance_status

    def search_target_alert_histogram(self, targets: List[str], time_range: int = 3600) -> Dict:
        """按照主机维度，检索最近的告警分布，默认取最近一小时"""
        if len(targets) == 0:
            return {"total": [], "targets": {}}

        request_data = {
            "bk_biz_ids": [self.collect_config.bk_biz_id],
            "query_string": " OR ".join(f"stategy_id : {sid}" for sid in self.strategy_ids),
        }

        handler = AlertQueryHandler(**request_data)
        # 计算检索的时长和步长
        start_time, end_time = int(time.time() - time_range), int(time.time())
        interval = handler.calculate_agg_interval(start_time, end_time, interval="auto")
        start_time = start_time // interval * interval
        end_time = end_time // interval * interval + interval
        # 以 ElastcisartchDSL 提供的语法组装 DSL 语句
        search_object = handler.get_search_object(start_time=start_time, end_time=end_time)
        search_object = handler.add_query_string(search_object)
        search_object.aggs.bucket("end_time", "filter", {"range": {"end_time": {"lte": end_time}}}).bucket(
            "end_alert", "filter", {"terms": {"status": [EventStatus.RECOVERED, EventStatus.CLOSED]}}
        ).bucket("targets", "terms", field="event.bk_host_id").bucket(
            "time", "date_histogram", field="end_time", fixed_interval=f"{interval}s"
        )
        search_object.aggs.bucket(
            "begin_time", "filter", {"range": {"begin_time": {"gte": start_time, "lte": end_time}}}
        ).bucket("targets", "terms", field="event.bk_host_id").bucket(
            "time", "date_histogram", field="begin_time", fixed_interval=f"{interval}s"
        )
        search_object.aggs.bucket("init_alert", "filter", {"range": {"begin_time": {"lt": start_time}}}).bucket(
            "targets", "terms", field="event.bk_host_id"
        )
        search_result = search_object[:0].execute()
        # 检索后的数据整理后，按照主机ID分桶存放，启动和结束记录还需要按照时间分桶存放
        init_alerts: Dict[str, int] = dict()
        begine_alerts: Dict[str, Dict[int][int]] = dict()
        end_alerts: Dict[str, Dict[int][int]] = dict()
        if search_result.aggs:
            for target_bucket in search_result.aggs.init_alert.targets.buckets:
                init_alerts[target_bucket.key] = target_bucket.doc_count
            for target_bucket in search_result.aggs.begin_time.targets.buckets:
                begine_alerts[target_bucket.key] = {}
                # 时间分桶的 KEY 默认是毫秒值
                for time_bucket in target_bucket.time.buckets:
                    begine_alerts[target_bucket.key][int(time_bucket.key_as_string) * 1000] = time_bucket.doc_count
            for target_bucket in search_result.aggs.end_time.end_alert.targets.buckets:
                end_alerts[target_bucket.key] = {}
                for time_bucket in target_bucket.time.buckets:
                    end_alerts[target_bucket.key][int(time_bucket.key_as_string) * 1000] = time_bucket.doc_count

        # 初始化主机分桶信息，每个分桶里按照时间分桶初始化 0
        ts_buckets = range(start_time, end_time, interval)
        targets_series: Dict[str, List] = {target: [[ts * 1000, 0] for ts in ts_buckets] for target in targets}
        for target, series in targets_series.items():
            init_cnt = init_alerts.get(target, 0)
            # 以一个主机例子，从最小时间开始迭代，比如初始3个告警，在第一个时间桶遇到2个新增，1个关闭，则最终为 3+2-1=4 个告警，以此类推
            for item in series:
                ts = item[0]
                begine_cnt = begine_alerts.get(target, {}).get(ts, 0)
                end_cnt = end_alerts.get(target, {}).get(ts, 0)
                item[1] = init_cnt + begine_cnt - end_cnt
                init_cnt = item[1]
        # 汇总计算总的告警数
        total_series: List = []
        for idx, item in enumerate(next(iter(targets_series.values()))):
            ts = item[0]
            cnt = sum(targets_series[target][idx][1] for target in targets)
            total_series.append([ts, cnt])

        return {"total": total_series, "targets": targets_series}


class IntervalOption(Enum):
    MINUTE = "minute"
    DAY = "day"


class TransferCountSeriesResource(BaseStatusResource):
    """查询数据量曲线，目前只支持分钟级和天级"""

    class RequestSerilizer(serializers.Serializer):
        collect_config_id = serializers.IntegerField(required=True, label="采集配置ID")
        start_time = serializers.IntegerField(required=True, label="开始时间")
        end_time = serializers.IntegerField(required=True, label="结束时间")
        interval_option = serializers.CharField(required=False, label="间隔选项", default=IntervalOption.MINUTE.value)

    def perform_request(self, validated_request_data: Dict):
        self.init_data(validated_request_data["collect_config_id"])
        interval_option = IntervalOption(validated_request_data["interval_option"])
        start_time = validated_request_data["start_time"]
        end_time = validated_request_data["end_time"]
        if interval_option == IntervalOption.MINUTE:
            interval = 1
            interval_unit = "m"
        else:
            interval = 1440
            interval_unit = "m"

        # 读取采集相关的指标列表
        metrics_alias = []
        metrics_query_configs = []
        metric_idx = 1

        for table in self.get_metrics_json():
            # 根据插件类型计算出入库 RT_ID
            for metric_name in table["metric_names"]:
                metric_alias = f"m{metric_idx}"
                metrics_query_configs.append(
                    {
                        "data_source_label": "bk_monitor",
                        "data_type_label": "time_series",
                        "metrics": [{"field": metric_name, "method": "COUNT", "alias": metric_alias}],
                        "table": table["table_id"],
                        "data_label": "",
                        "index_set_id": None,
                        "group_by": [],
                        "where": [{"key": "bk_collect_config_id", "method": "eq", "value": [self.collect_config_id]}],
                        "interval": interval,
                        "interval_unit": interval_unit,
                        "time_field": None,
                        "filter_dict": {},
                        "functions": [],
                    }
                )
                metrics_alias.append(metric_alias)
                metric_idx += 1

        query_params = {
            "bk_biz_id": self.collect_config.bk_biz_id,
            "query_configs": metrics_query_configs,
            "expression": "+".join(f"({alias} or vector(0))" for alias in metrics_alias),
            "functions": [],
            "alias": "result",
            "name": "COUNT(ALL)",
            "start_time": start_time,
            "end_time": end_time,
            "slimit": 500,
            "down_sample_range": "",
        }
        return resource.grafana.graph_unify_query(query_params)["series"]


class TransferLatestMsgResource(BaseStatusResource):
    class RequestSerilizer(serializers.Serializer):
        collect_config_id = serializers.IntegerField(required=True, label="采集配置ID")

    def perform_request(self, validated_request_data):
        self.init_data(validated_request_data["collect_config_id"])
        messages = []
        for table in self.get_metrics_json():
            for metric_name in table["metric_names"]:
                messages.extend(self.query_latest_metric_msg(table["table_id"], metric_name))
                if len(messages) > 10:
                    return messages[:10]
        return messages

    def query_latest_metric_msg(self, table_id: str, metric_name: str, time_range: int = 600) -> List[str]:
        """查询一个指标最近10分钟的最新数据"""
        start_time, end_time = int(time.time() - time_range), int(time.time())
        query_params = {
            "bk_biz_id": self.collect_config.bk_biz_id,
            "query_configs": [
                {
                    "data_source_label": "prometheus",
                    "data_type_label": "time_series",
                    "promql": "bkmonitor:{table}:{metric}{{{conds}}}[1m]".format(
                        table=table_id.replace('.', ':'),
                        metric=metric_name,
                        conds=f"bk_collect_config_id=\"{self.collect_config_id}\"",
                    ),
                    "interval": 60,
                    "alias": "a",
                }
            ],
            "expression": "",
            "alias": "a",
            "start_time": start_time,
            "end_time": end_time,
            "slimit": 500,
            "down_sample_range": "",
        }
        series = resource.grafana.graph_unify_query(query_params)["series"]
        msgs = []
        for s in series:
            msg = "{metric}{dims} {val}".format(metric=metric_name, dims=s["target"], val=s["datapoints"][-1][0])
            msgs.append({"message": msg, "time": s["datapoints"][-1][1]})
        return msgs


class StorageStatusResource(Resource):
    """获取存储状态"""

    class RequestSerilizer(serializers.Serializer):
        collect_config_id = serializers.IntegerField(required=True, label="采集配置ID")

    def perform_request(self, validated_request_data):
        return {
            "info": [
                {"key": "index", "name": "存储索引名", "value": "trace_agg_scene"},
                {"key": "cluster_name", "name": "存储集群", "value": "默认集群"},
                {"key": "expire_time", "name": "过期时间", "value": "7天"},
                {"key": "copy", "name": "副本数", "value": "1"},
            ],
            "status": [
                {
                    "name": "集群状态",
                    "content": {
                        "keys": [
                            {"key": "index", "name": "索引"},
                            {"key": "running_status", "name": "运行状态"},
                            {"key": "copy", "name": "主分片"},
                            {"key": "v_copy", "name": "副本分片"},
                        ],
                        "values": [
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                        ],
                    },
                },
                {
                    "name": "索引状态",
                    "content": {
                        "keys": [
                            {"key": "index", "name": "索引"},
                            {"key": "running_status", "name": "运行状态"},
                            {"key": "copy", "name": "主分片"},
                            {"key": "v_copy", "name": "负分片"},
                        ],
                        "values": [
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                            {"index": "object/list", "running_status": "正常", "copy": 8, "v_copy": 8},
                        ],
                    },
                },
            ],
        }
