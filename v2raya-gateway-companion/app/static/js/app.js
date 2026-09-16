const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

createApp({
  setup() {
    const currentTab = ref('sniffer');
    const targetIp = ref('');
    const lanDevices = ref([]);
    const monitorStatus = ref({ is_running: false, elapsed_seconds: 0 });
    const alerts = ref([]);
    
    // Manual tab
    const manualInput = ref('');
    const manualAnalysis = ref({});
    const manualProbe = ref(null);
    const manualAction = ref('proxy');
    const probing = ref(false);

    // Rules tab
    const rules = ref([]);
    const rawContent = ref('');
    const showRawEditor = ref(false);
    const searchQuery = ref('');

    // Toast
    const toast = ref({ show: false, message: '', type: 'success' });
    const showToast = (message, type = 'success') => {
      toast.value = { show: true, message, type };
      setTimeout(() => { toast.value.show = false; }, 3500);
    };

    // WebSocket
    let ws = null;
    let timerInterval = null;

    const connectWebSocket = () => {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${protocol}//${location.host}/ws/live`);
      
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'NEW_BLOCKED_DOMAIN') {
            alerts.value.unshift(msg.data);
            showToast(`🚨 捕获到被墙请求: ${msg.data.domain}`, 'error');
          } else if (msg.type === 'RULES_UPDATED') {
            fetchRules();
          } else if (msg.type === 'MONITOR_STATUS_CHANGED') {
            monitorStatus.value = msg.data;
          } else if (msg.type === 'ALERTS_CLEARED') {
            alerts.value = [];
          }
        } catch (e) {
          console.error(e);
        }
      };

      ws.onclose = () => {
        setTimeout(connectWebSocket, 3000);
      };
    };

    // Load initial data
    const fetchDevices = async () => {
      try {
        const res = await fetch('/api/devices');
        lanDevices.value = await res.json();
      } catch (e) {}
    };

    const fetchStatus = async () => {
      try {
        const res = await fetch('/api/monitor/status');
        monitorStatus.value = await res.json();
      } catch (e) {}
    };

    const fetchAlerts = async () => {
      try {
        const res = await fetch('/api/monitor/alerts');
        alerts.value = await res.json();
      } catch (e) {}
    };

    const fetchRules = async () => {
      try {
        const res = await fetch('/api/rules');
        const data = await res.json();
        rules.value = data.rules || [];
        rawContent.value = data.raw || '';
      } catch (e) {}
    };

    // Sniffer Controls
    const startMonitoring = async () => {
      if (!targetIp.value) {
        showToast('请先输入或选择目标设备 IP', 'error');
        return;
      }
      try {
        const res = await fetch('/api/monitor/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_ip: targetIp.value, duration_seconds: 0 })
        });
        const data = await res.json();
        if (data.success) {
          monitorStatus.value.is_running = true;
          showToast(`已启动对 ${targetIp.value} 的定向流量监测`);
        }
      } catch (e) {
        showToast('启动监测失败', 'error');
      }
    };

    const stopMonitoring = async () => {
      try {
        await fetch('/api/monitor/stop', { method: 'POST' });
        monitorStatus.value.is_running = false;
        showToast('监测计划已停止');
      } catch (e) {
        showToast('停止监测失败', 'error');
      }
    };

    const clearAlerts = async () => {
      try {
        await fetch('/api/monitor/alerts', { method: 'DELETE' });
        alerts.value = [];
        showToast('已清空记录');
      } catch (e) {}
    };

    const triggerSimulate = async () => {
      const sampleDomains = [
        'www.pornhub.com', 
        'api.telegram.org', 
        'chat.openai.com', 
        'sub.tiktokv.com'
      ];
      const randomDomain = sampleDomains[Math.floor(Math.random() * sampleDomains.length)];
      try {
        await fetch('/api/monitor/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: randomDomain, target_ip: targetIp.value || '192.168.1.100' })
        });
        showToast(`已模拟访问: ${randomDomain}`);
      } catch (e) {}
    };

    // Manual tab methods
    let inputTimeout = null;
    const onManualInputChanged = () => {
      clearTimeout(inputTimeout);
      inputTimeout = setTimeout(async () => {
        if (!manualInput.value.trim()) {
          manualAnalysis.value = {};
          manualProbe.value = null;
          return;
        }
        try {
          const res = await fetch('/api/domain/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: manualInput.value })
          });
          manualAnalysis.value = await res.json();
        } catch (e) {}
      }, 300);
    };

    const useRootDomain = () => {
      if (manualAnalysis.value && manualAnalysis.value.root_domain) {
        manualInput.value = manualAnalysis.value.root_domain;
        onManualInputChanged();
        showToast(`已切换为一级根域名: ${manualAnalysis.value.root_domain}`);
      }
    };

    const probeManualDomain = async () => {
      if (!manualAnalysis.value.hostname) return;
      probing.value = true;
      try {
        const res = await fetch('/api/domain/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: manualAnalysis.value.hostname, force_refresh: true })
        });
        const data = await res.json();
        manualProbe.value = data.probe;
        manualProbe.value.already_proxied = data.already_proxied;
      } catch (e) {
        showToast('探测失败', 'error');
      } finally {
        probing.value = false;
      }
    };

    const addManualRule = async () => {
      const target = manualAnalysis.value.hostname;
      if (!target) return;
      await addRule(target, manualAction.value, manualAnalysis.value.is_subdomain ? 'full' : 'domain');
      manualInput.value = '';
      manualAnalysis.value = {};
      manualProbe.value = null;
    };

    // Add Rule general
    const addRule = async (domain, action = 'proxy', match_type = 'domain') => {
      try {
        const res = await fetch('/api/rules/add', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain, action, match_type })
        });
        const data = await res.json();
        if (data.success) {
          showToast(`已成功添加规则并同步到 v2rayA: ${domain}`);
          fetchRules();
        }
      } catch (e) {
        showToast('添加规则失败', 'error');
      }
    };

    const deleteRule = async (target) => {
      if (!confirm(`确定要从 RoutingA 中删除 ${target} 吗？`)) return;
      try {
        await fetch(`/api/rules?target=${encodeURIComponent(target)}`, { method: 'DELETE' });
        showToast(`已删除: ${target}`);
        fetchRules();
      } catch (e) {
        showToast('删除失败', 'error');
      }
    };

    const optimizeRules = async () => {
      try {
        const res = await fetch('/api/rules/optimize', { method: 'POST' });
        const data = await res.json();
        showToast(`优化完成，已清理 ${data.cleaned_count} 条多余冗余规则`);
        fetchRules();
      } catch (e) {
        showToast('优化失败', 'error');
      }
    };

    const saveRawRules = async () => {
      try {
        await fetch('/api/rules/raw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: rawContent.value })
        });
        showToast('纯文本规则已保存并应用到 v2rayA');
        fetchRules();
      } catch (e) {
        showToast('保存失败', 'error');
      }
    };

    // Group rules by category
    const groupedRules = computed(() => {
      const q = searchQuery.value.toLowerCase().trim();
      const groups = {};
      for (const r of rules.value) {
        if (q && !r.target.includes(q)) continue;
        const cat = r.category || '未分类';
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(r);
      }
      return groups;
    });

    const formatTime = (ts) => {
      if (!ts) return '';
      const d = new Date(ts * 1000);
      return d.toLocaleTimeString();
    };

    onMounted(() => {
      connectWebSocket();
      fetchDevices();
      fetchStatus();
      fetchAlerts();
      fetchRules();

      timerInterval = setInterval(() => {
        if (monitorStatus.value.is_running) {
          monitorStatus.value.elapsed_seconds += 1;
        }
      }, 1000);
    });

    onUnmounted(() => {
      if (ws) ws.close();
      if (timerInterval) clearInterval(timerInterval);
    });

    return {
      currentTab,
      targetIp,
      lanDevices,
      monitorStatus,
      alerts,
      manualInput,
      manualAnalysis,
      manualProbe,
      manualAction,
      probing,
      rules,
      rawContent,
      showRawEditor,
      searchQuery,
      groupedRules,
      toast,
      startMonitoring,
      stopMonitoring,
      clearAlerts,
      triggerSimulate,
      onManualInputChanged,
      useRootDomain,
      probeManualDomain,
      addManualRule,
      addRule,
      deleteRule,
      optimizeRules,
      saveRawRules,
      formatTime
    };
  }
}).mount('#app');
