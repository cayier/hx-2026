"use strict";

const $ = (id) => document.getElementById(id);
const pages = {
  alerts: {
    title: "告警工作台", subtitle: "接入安全设备告警，跟踪研判与责任人通知。",
    list: "告警记录", add: "接入告警",
    columns: ["告警", "关联资产", "风险", "评分", "状态", "操作"],
    fields: [
      ["id", "告警编号"], ["title", "告警标题"], ["source", "告警来源"],
      ["address", "资产地址"], ["severity", "风险等级", ["低危", "中危", "高危", "严重"]],
      ["description", "告警描述", "textarea"], ["initial", "初步研判", "textarea"],
    ],
  },
  assets: {
    title: "资产台账", subtitle: "根据告警中的资产地址匹配责任人和评分权重。",
    list: "资产记录", add: "登记资产", columns: ["资产名称", "地址", "责任人", "风险权重"],
    fields: [["address", "资产地址"], ["name", "资产名称"], ["owner", "责任人标识"], ["criticality", "风险权重（0–20）", "number"]],
  },
  knowledge: {
    title: "分行知识库", subtitle: "维护告警研判可引用的历史记录、运维手册和应急预案。",
    list: "知识条目", add: "录入知识", columns: ["标题", "类型", "关键词", "操作"],
    fields: [
      ["title", "标题"], ["kind", "类别", ["历史告警", "运维手册", "应急预案", "安全手册"]],
      ["keywords", "检索关键词（使用逗号分隔）"], ["body", "内容", "textarea"],
    ],
  },
};
let current = "alerts";
let data;
const retryable = ["待研判", "研判失败", "通知失败", "待分派"];

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

async function api(path, payload) {
  const options = payload === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  };
  const response = await fetch("/api/" + path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "请求失败");
  return result;
}

function notice(message) {
  $("notice").textContent = message;
  $("notice").hidden = !message;
}

async function refresh() {
  data = await api("overview");
  render();
}

function render() {
  const page = pages[current];
  $("crumb").textContent = page.title;
  $("title").textContent = page.title;
  $("subtitle").textContent = page.subtitle;
  $("list-title").textContent = page.list;
  $("add").textContent = "＋ " + page.add;
  $("mode").textContent = data.demo ? "本地演示 · 模拟数据" : "行内对接模式";
  $("filter").hidden = current !== "alerts";
  $("metrics").hidden = current !== "alerts";
  if (current === "alerts") {
    const alerts = data.alerts;
    const counts = [
      ["全部告警", alerts.length],
      ["高危与严重", alerts.filter((row) => ["高危", "严重"].includes(row.severity)).length],
      ["待跟进", alerts.filter((row) => retryable.includes(row.state) || row.state === "处理中").length],
      ["已完成", alerts.filter((row) => row.state === "已完成").length],
    ];
    $("metrics").replaceChildren(...counts.map(([label, value]) => {
      const card = el("article", undefined, "metric");
      card.append(el("p", label), el("strong", value));
      return card;
    }));
  }
  const heading = el("tr");
  heading.append(...page.columns.map((column) => el("th", column)));
  $("columns").replaceChildren(heading);
  const query = $("search").value.trim().toLowerCase();
  const state = $("filter").value;
  const records = data[current].filter((row) => {
    const match = Object.values(row).some((value) => typeof value === "string" && value.toLowerCase().includes(query));
    return match && (current !== "alerts" || !state || state === row.state);
  });
  $("count").textContent = records.length + " 条记录" + (current === "alerts" ? " · 研判阈值 " + data.threshold : "");
  $("rows").replaceChildren(...records.map(rowNode));
  if (!records.length) {
    const row = el("tr");
    const cell = el("td", "暂无符合条件的记录");
    cell.colSpan = page.columns.length;
    row.append(cell);
    $("rows").append(row);
  }
}

function cell(value, subtext) {
  const td = el("td");
  td.append(value instanceof Node ? value : document.createTextNode(value ?? "—"));
  if (subtext) td.append(el("small", subtext));
  return td;
}

function rowNode(record) {
  const tr = el("tr");
  const detail = el("button", "详情", "link");
  detail.addEventListener("click", () => showDetail(record));
  if (current === "alerts") {
    tr.append(cell(record.title, record.id + " · " + record.source),
      cell(record.asset || "未匹配资产", record.address), cell(el("span", record.severity, "chip " + record.severity)),
      cell(record.score), cell(el("span", record.state, "chip " + record.state)), cell(detail));
  } else if (current === "assets") {
    tr.append(cell(record.name), cell(record.address), cell(record.owner), cell("+" + record.criticality));
  } else {
    tr.append(cell(record.title), cell(record.kind), cell(record.keywords), cell(detail));
  }
  return tr;
}

function open(title, content) {
  $("dialog-title").textContent = title;
  $("dialog-body").replaceChildren(content);
  if (!$("dialog").open) $("dialog").showModal();
}

function showDetail(record) {
  const section = el("section");
  const list = el("dl");
  const result = record.result;
  const details = current === "alerts" ? [
    ["告警编号", record.id], ["接入时间", new Date(record.created).toLocaleString("zh-CN")],
    ["来源", record.source], ["资产", record.asset], ["地址", record.address], ["责任人", record.owner],
    ["风险和评分", record.severity + " · " + record.score], ["描述", record.description], ["初步研判", record.initial],
    ["处理状态", record.state], ["研判来源", result?.mode], ["研判结果", result?.summary],
    ["处置建议", result?.recommendation], ["知识引用", result?.references.map((ref) => ref.title).join("、")],
    ["通知状态", record.notification],
  ] : [["类别", record.kind], ["检索关键词", record.keywords], ["正文", record.body]];
  if (record.error) details.push(["处理错误", record.error]);
  for (const [label, value] of details) list.append(el("dt", label), el("dd", value || "—"));
  section.append(list);
  if (current === "alerts" && retryable.includes(record.state)) {
    const button = el("button", "重试处理", "primary");
    const error = el("p", "", "error");
    error.setAttribute("role", "status");
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("retry", { id: record.id });
        await refresh();
        showDetail(data.alerts.find((row) => row.id === record.id));
      } catch (failure) {
        error.textContent = failure.message;
      } finally {
        button.disabled = false;
      }
    });
    section.append(button, error);
  }
  open(record.title, section);
}

function showForm() {
  const tab = current;
  const page = pages[tab];
  const form = el("form");
  for (const [name, label, type] of page.fields) {
    const field = el("label", label);
    const input = el(Array.isArray(type) ? "select" : type === "textarea" ? "textarea" : "input");
    if (Array.isArray(type)) input.append(...type.map((option) => el("option", option)));
    if (type === "number") {
      input.type = "number";
      input.min = "0";
      input.max = "20";
      input.value = "0";
    }
    input.name = name;
    input.required = true;
    field.append(input);
    form.append(field);
  }
  const error = el("p", "", "error");
  error.setAttribute("role", "status");
  const submit = el("button", "保存", "primary");
  form.append(error, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    const payload = Object.fromEntries(new FormData(form));
    if (tab === "assets") payload.criticality = Number(payload.criticality);
    try {
      await api(tab, payload);
      await refresh();
      $("dialog").close();
    } catch (failure) {
      error.textContent = failure.message;
    } finally {
      submit.disabled = false;
    }
  });
  open(page.add, form);
}

for (const button of document.querySelectorAll(".nav")) {
  button.addEventListener("click", () => {
    current = button.dataset.page;
    for (const nav of document.querySelectorAll(".nav")) {
      nav.classList.toggle("active", nav === button);
      if (nav === button) nav.setAttribute("aria-current", "page");
      else nav.removeAttribute("aria-current");
    }
    $("search").value = "";
    $("filter").value = "";
    if (data) render();
  });
}
$("add").addEventListener("click", showForm);
$("close").addEventListener("click", () => $("dialog").close());
$("refresh").addEventListener("click", load);
$("search").addEventListener("input", () => data && render());
$("filter").addEventListener("change", () => data && render());
function load() {
  notice("");
  refresh().catch((error) => notice(error.message));
}
load();
