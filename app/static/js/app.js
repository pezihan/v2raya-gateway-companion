const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

const GEOSITE_PRESETS = [
  { value: 'geosite:cn', label: '🇨🇳 中国大陆主流域名 (直连推荐)', defaultAction: 'direct', defaultCategory: '中国大陆及私有地址直连' },
  { value: 'geosite:category-ads-all', label: '🚫 全网常见广告与恶意跟踪拦截 (拦截推荐)', defaultAction: 'block', defaultCategory: '广告与安全拦截' },
  { value: 'geosite:geolocation-!cn', label: '🌐 全球非大陆常见国外网站 (代理推荐)', defaultAction: 'proxy', defaultCategory: '自定义需要代理的域名' },
  { value: 'geosite:google', label: '🔍 Google 官方全家桶服务', defaultAction: 'proxy', defaultCategory: 'Google' },
  { value: 'geosite:telegram', label: '✈️ Telegram 官方所有域名', defaultAction: 'proxy', defaultCategory: 'Telegram' },
  { value: 'geosite:openai', label: '🤖 OpenAI / ChatGPT 官方服务', defaultAction: 'proxy', defaultCategory: 'AI 与科研服务' },
  { value: 'geosite:github', label: '🐙 GitHub 代码托管与开发者服务', defaultAction: 'proxy', defaultCategory: '开发者工具' },
  { value: 'geosite:youtube', label: '📺 YouTube 视频平台', defaultAction: 'proxy', defaultCategory: '流媒体服务' },
  { value: 'geosite:netflix', label: '🎬 Netflix 奈飞流媒体', defaultAction: 'proxy', defaultCategory: '流媒体服务' },
  { value: 'geosite:twitter', label: '✖️ X (原 Twitter)', defaultAction: 'proxy', defaultCategory: '社交媒体' },
  { value: 'geosite:facebook', label: '👤 Facebook / Instagram / Meta', defaultAction: 'proxy', defaultCategory: '社交媒体' },
  { value: 'geosite:spotify', label: '🎵 Spotify 音乐流媒体', defaultAction: 'proxy', defaultCategory: '流媒体服务' },
  { value: 'geosite:disney', label: '🏰 Disney+ 迪士尼流媒体', defaultAction: 'proxy', defaultCategory: '流媒体服务' },
  { value: 'geosite:apple', label: '🍎 Apple 苹果官方服务', defaultAction: 'direct', defaultCategory: '系统服务' },
  { value: 'geosite:microsoft', label: '🪟 Microsoft 微软官方服务', defaultAction: 'direct', defaultCategory: '系统服务' },
  { value: 'geosite:steam', label: '🎮 Steam 游戏与社区', defaultAction: 'proxy', defaultCategory: '游戏与娱乐' },
  { value: 'geosite:bilibili', label: '📺 哔哩哔哩 Bilibili', defaultAction: 'direct', defaultCategory: '国内网站' },
  { value: 'ext:"LoyalsoldierSite.dat:gfw"', label: '🛡️ GFWList 阻断域名规则集 (DAT)', defaultAction: 'proxy', defaultCategory: 'GFWList' },
  { value: 'ext:"LoyalsoldierSite.dat:greatfire"', label: '🛡️ GreatFire 阻断列表 (DAT)', defaultAction: 'proxy', defaultCategory: 'GFWList' }
];

const GEOIP_PRESETS = [
  { value: 'geoip:private, geoip:cn', label: '🏠 🇨🇳 私有内网 + 中国大陆全部 IP (强烈推荐直连)', defaultAction: 'direct', defaultCategory: '中国大陆及私有地址直连' },
  { value: 'geoip:private', label: '🏠 局域网私有地址 (192.168.x / 10.x / 172.16.x)', defaultAction: 'direct', defaultCategory: '中国大陆及私有地址直连' },
  { value: 'geoip:cn', label: '🇨🇳 中国大陆境内全部 IP', defaultAction: 'direct', defaultCategory: '中国大陆及私有地址直连' },
  { value: 'geoip:hk, geoip:mo', label: '🇭🇰 🇲🇴 中国香港 + 澳门地区 IP', defaultAction: 'proxy', defaultCategory: '香港 / 澳门 IP' },
  { value: 'geoip:hk', label: '🇭🇰 中国香港 IP', defaultAction: 'proxy', defaultCategory: '香港 / 澳门 IP' },
  { value: 'geoip:mo', label: '🇲🇴 中国澳门 IP', defaultAction: 'proxy', defaultCategory: '香港 / 澳门 IP' },
  { value: 'geoip:tw', label: '🇹🇼 中国台湾 IP', defaultAction: 'proxy', defaultCategory: '港台及海外 IP' },
  { value: 'geoip:us', label: '🇺🇸 美国 IP', defaultAction: 'proxy', defaultCategory: '港台及海外 IP' },
  { value: 'geoip:jp', label: '🇯🇵 日本 IP', defaultAction: 'proxy', defaultCategory: '港台及海外 IP' },
  { value: 'geoip:sg', label: '🇸🇬 新加坡 IP', defaultAction: 'proxy', defaultCategory: '港台及海外 IP' },
  { value: 'geoip:kr', label: '🇰🇷 韩国 IP', defaultAction: 'proxy', defaultCategory: '港台及海外 IP' },
  { value: 'geoip:telegram', label: '✈️ Telegram 官方服务器 IP 库', defaultAction: 'proxy', defaultCategory: 'Telegram 数据中心 IP' },
  { value: 'geoip:!cn', label: '🌍 非中国大陆全部境外 IP (全翻墙代理)', defaultAction: 'proxy', defaultCategory: '境外全部 IP 代理' }
];

createApp({
  setup() {
    const currentTab = ref('rules'); // default to rules tab so user immediately sees management
    const targetIp = ref('');
    const lanDevices = ref([]);
    const monitorStatus = ref({ is_running: false, elapsed_seconds: 0 });
    const alerts = ref([]);
    const storageInfo = ref({});
    
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
    const ruleAudit = ref({ total_issues: 0, issues: [] });

    // Available categories computed from loaded rules
    const availableCategories = computed(() => {
      const cats = new Set();
      for (const r of rules.value) {
        if (r.category && r.category !== '系统策略') {
          cats.add(r.category);
        }
      }
      if (!cats.size) {
        cats.add('中国大陆及私有地址直连');
        cats.add('香港 / 澳门 IP');
        cats.add('自定义需要代理的域名');
        cats.add('自定义代理');
      }
      return Array.from(cats);
    });

    // Modal state for Add / Edit
    const modal = ref({
      show: false,
      isEdit: false,
      ruleType: 'domain', // 'domain' | 'geosite' | 'geoip' | 'cidr'
      oldTarget: '',
      target: '',
      geositePreset: 'geosite:cn',
      geoipPreset: 'geoip:private, geoip:cn',
      customTarget: '',
      match_type: 'domain',
      action: 'proxy',
      categoryMode: 'select', // 'select' | 'new'
      category: '自定义代理',
      newCategoryInput: '',
      suggestedRoot: null
    });

    // Toast
    const toast = ref({ show: false, message: '', type: 'success' });
    const showToast = (message, type = 'success') => {
      toast.value = { show: true, message, type };
      setTimeout(() => { toast.value.show = false; }, 3500);
    };

    // Auth State
    const authRequired = ref(true);
    const isAuthenticated = ref(false);
    const authChecked = ref(false);
    const loginPassword = ref('');
    const loginError = ref('');
    const isLoggingIn = ref(false);
    const showPassword = ref(false);

    const getAuthToken = () => localStorage.getItem('companion_token') || '';

    // Auth-aware Fetch Wrapper
    const fetch = async (url, options = {}) => {
      const token = getAuthToken();
      const opts = { ...options };
      const headers = opts.headers ? { ...opts.headers } : {};
      if (token && !headers['Authorization']) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      opts.headers = headers;
      const res = await window.fetch(url, opts);
      if (res.status === 401 && !url.includes('/api/auth/')) {
        isAuthenticated.value = false;
        localStorage.removeItem('companion_token');
      }
      return res;
    };

    // WebSocket
    let ws = null;
    let timerInterval = null;

    const connectWebSocket = () => {
      if (!isAuthenticated.value) return;
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const token = getAuthToken();
      const tokenParam = token ? `?token=${encodeURIComponent(token)}` : '';
      ws = new WebSocket(`${protocol}//${location.host}/ws/live${tokenParam}`);
      
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'NEW_BLOCKED_DOMAIN') {
            alerts.value.unshift(msg.data);
            showToast(`🚨 捕获到被墙请求: ${msg.data.domain}`, 'error');
          } else if (msg.type === 'RULES_UPDATED') {
            fetchRules();
            if (msg.source === 'v2rayA_auto_sync') {
              showToast('⚡ 检测到 v2rayA 规则变动，已自动同步！');
            }
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
        if (isAuthenticated.value) {
          setTimeout(connectWebSocket, 3000);
        }
      };
    };

    const initApp = () => {
      connectWebSocket();
      fetchDevices();
      fetchStatus();
      fetchAlerts();
      fetchRules();
    };

    const checkAuthStatus = async () => {
      try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        authRequired.value = data.auth_required;
        isAuthenticated.value = !data.auth_required || data.authenticated;
        if (isAuthenticated.value) {
          initApp();
        }
      } catch (e) {
        isAuthenticated.value = false;
      } finally {
        authChecked.value = true;
      }
    };

    const handleLogin = async () => {
      if (!loginPassword.value.trim()) {
        loginError.value = '请输入访问密码';
        return;
      }
      isLoggingIn.value = true;
      loginError.value = '';
      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: loginPassword.value.trim() })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          localStorage.setItem('companion_token', data.token);
          isAuthenticated.value = true;
          loginPassword.value = '';
          showToast('🎉 解锁成功！欢迎使用');
          initApp();
        } else {
          loginError.value = data.detail || '密码错误，请重新输入';
        }
      } catch (e) {
        loginError.value = '连接服务器失败';
      } finally {
        isLoggingIn.value = false;
      }
    };

    const handleLogout = async () => {
      try {
        await fetch('/api/auth/logout', { method: 'POST' });
      } catch (e) {}
      localStorage.removeItem('companion_token');
      isAuthenticated.value = false;
      if (ws) ws.close();
      showToast('已安全退出登录');
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
        const res = await fetch('/api/status');
        const data = await res.json();
        storageInfo.value = data.storage || {};
        monitorStatus.value = data.sniffer || {};
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
        ruleAudit.value = data.audit || { total_issues: 0, issues: [] };
        if (data.storage) {
          storageInfo.value = data.storage;
        }
      } catch (e) {}
    };

    // Modal Type and Preset Helpers
    const setModalRuleType = (type) => {
      modal.value.ruleType = type;
      if (!modal.value.isEdit) {
        if (type === 'geosite') {
          const p = GEOSITE_PRESETS.find(x => x.value === modal.value.geositePreset) || GEOSITE_PRESETS[0];
          modal.value.action = p.defaultAction || 'direct';
          if (availableCategories.value.includes(p.defaultCategory)) {
            modal.value.category = p.defaultCategory;
          }
        } else if (type === 'geoip') {
          const p = GEOIP_PRESETS.find(x => x.value === modal.value.geoipPreset) || GEOIP_PRESETS[0];
          modal.value.action = p.defaultAction || 'direct';
          if (availableCategories.value.includes(p.defaultCategory)) {
            modal.value.category = p.defaultCategory;
          }
        }
      }
    };

    const onGeositePresetChange = () => {
      if (modal.value.geositePreset !== '__custom__' && !modal.value.isEdit) {
        const p = GEOSITE_PRESETS.find(x => x.value === modal.value.geositePreset);
        if (p) {
          modal.value.action = p.defaultAction || 'proxy';
          if (availableCategories.value.includes(p.defaultCategory)) {
            modal.value.category = p.defaultCategory;
          }
        }
      }
    };

    const onGeoipPresetChange = () => {
      if (modal.value.geoipPreset !== '__custom__' && !modal.value.isEdit) {
        const p = GEOIP_PRESETS.find(x => x.value === modal.value.geoipPreset);
        if (p) {
          modal.value.action = p.defaultAction || 'direct';
          if (availableCategories.value.includes(p.defaultCategory)) {
            modal.value.category = p.defaultCategory;
          }
        }
      }
    };

    const toggleCategoryMode = () => {
      if (modal.value.categoryMode === 'select') {
        modal.value.categoryMode = 'new';
        modal.value.newCategoryInput = '';
      } else {
        modal.value.categoryMode = 'select';
        modal.value.category = availableCategories.value[0] || '自定义代理';
      }
    };

    const onCategorySelectChange = () => {
      if (modal.value.category === '__NEW_CATEGORY__') {
        modal.value.categoryMode = 'new';
        modal.value.newCategoryInput = '';
      }
    };

    const getRuleBadge = (rule) => {
      const targetLower = (rule.target || '').toLowerCase();
      if (targetLower.startsWith('geosite:')) {
        return { text: 'GeoSite 预设集', class: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' };
      }
      if (targetLower.startsWith('geoip:')) {
        return { text: 'GeoIP 预设库', class: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' };
      }
      if (rule.target_type === 'ip' || rule.match_type === 'cidr') {
        return { text: 'IP / CIDR 网段', class: 'text-amber-400 bg-amber-500/10 border-amber-500/20' };
      }
      if (targetLower.startsWith('ext:')) {
        return { text: '外部规则 (DAT)', class: 'text-purple-400 bg-purple-500/10 border-purple-500/20' };
      }
      if (rule.match_type === 'full') {
        return { text: '精准域名 (full)', class: 'text-blue-400 bg-blue-500/10 border-blue-500/20' };
      }
      if (rule.match_type === 'keyword') {
        return { text: '关键字 (keyword)', class: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20' };
      }
      if (rule.match_type === 'regexp') {
        return { text: '正则 (regexp)', class: 'text-pink-400 bg-pink-500/10 border-pink-500/20' };
      }
      return { text: '泛域名 (domain)', class: 'text-slate-400 bg-slate-800/80 border-slate-700' };
    };

    const getRuleFooter = (rule) => {
      const targetLower = (rule.target || '').toLowerCase();
      if (targetLower.startsWith('geosite:')) {
        return 'GeoSite 域名预设集合';
      }
      if (targetLower.startsWith('geoip:')) {
        return 'GeoIP 国家/地区地址库';
      }
      if (rule.target_type === 'ip' || rule.match_type === 'cidr') {
        return 'CIDR IP 网段';
      }
      if (targetLower.startsWith('ext:')) {
        return 'DAT 外部扩展规则';
      }
      if (rule.match_type === 'full') {
        return '仅限该完整主机名';
      }
      if (rule.match_type === 'keyword') {
        return '关键词模糊匹配';
      }
      if (rule.match_type === 'regexp') {
        return '正则表达式匹配';
      }
      return '通配该站全部二级/三级子域';
    };

    // Modal Operations (Add / Edit)
    const openAddModal = () => {
      const defaultCat = availableCategories.value[0] || '自定义代理';
      modal.value = {
        show: true,
        isEdit: false,
        ruleType: 'domain',
        oldTarget: '',
        target: '',
        geositePreset: 'geosite:cn',
        geoipPreset: 'geoip:private, geoip:cn',
        customTarget: '',
        match_type: 'domain',
        action: 'proxy',
        categoryMode: 'select',
        category: defaultCat,
        newCategoryInput: '',
        suggestedRoot: null
      };
    };

    const openEditModal = (rule) => {
      const targetLower = (rule.target || '').toLowerCase().trim();
      let ruleType = 'domain';
      let geositePreset = 'geosite:cn';
      let geoipPreset = 'geoip:private, geoip:cn';
      let customTarget = '';
      let target = rule.target;

      if (targetLower.startsWith('geosite:') || targetLower.startsWith('ext:')) {
        ruleType = 'geosite';
        const found = GEOSITE_PRESETS.find(p => p.value.toLowerCase() === targetLower);
        if (found) {
          geositePreset = found.value;
        } else {
          geositePreset = '__custom__';
          customTarget = rule.target;
        }
      } else if (targetLower.startsWith('geoip:')) {
        ruleType = 'geoip';
        const normTarget = targetLower.replace(/\s*,\s*/g, ', ');
        const found = GEOIP_PRESETS.find(p => p.value.toLowerCase().replace(/\s*,\s*/g, ', ') === normTarget);
        if (found) {
          geoipPreset = found.value;
        } else {
          geoipPreset = '__custom__';
          customTarget = rule.target;
        }
      } else if (rule.target_type === 'ip' || rule.match_type === 'cidr' || targetLower.includes('/') || /^[\d.:]+$/.test(targetLower)) {
        ruleType = 'cidr';
        target = rule.target;
      } else {
        ruleType = 'domain';
        target = rule.target;
      }

      modal.value = {
        show: true,
        isEdit: true,
        ruleType,
        oldTarget: rule.target,
        target,
        geositePreset,
        geoipPreset,
        customTarget,
        match_type: rule.match_type || 'domain',
        action: rule.action || 'proxy',
        categoryMode: 'select',
        category: rule.category || (availableCategories.value[0] || '自定义代理'),
        newCategoryInput: '',
        suggestedRoot: rule.has_www ? rule.suggested_root : null
      };
    };

    let modalInputTimer = null;
    const onModalTargetInput = () => {
      clearTimeout(modalInputTimer);
      modalInputTimer = setTimeout(async () => {
        const text = modal.value.target.trim();
        if (!text) {
          modal.value.suggestedRoot = null;
          return;
        }
        try {
          const res = await fetch('/api/domain/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: text })
          });
          const data = await res.json();
          if (data.success) {
            if (data.is_subdomain && data.suggested_root) {
              modal.value.suggestedRoot = data.suggested_root;
            } else {
              modal.value.suggestedRoot = null;
            }
          }
        } catch (e) {}
      }, 300);
    };

    const submitModal = async () => {
      let targetValue = '';
      let targetType = 'domain';
      let matchType = 'domain';

      if (modal.value.ruleType === 'domain') {
        targetValue = modal.value.target.trim();
        targetType = 'domain';
        matchType = modal.value.match_type;
        if (!targetValue) {
          showToast('请输入目标域名', 'error');
          return;
        }
      } else if (modal.value.ruleType === 'geosite') {
        if (modal.value.geositePreset === '__custom__') {
          targetValue = modal.value.customTarget.trim();
        } else {
          targetValue = modal.value.geositePreset;
        }
        targetType = 'domain';
        matchType = 'geosite';
        if (!targetValue) {
          showToast('请选择或输入 GeoSite 预设代码', 'error');
          return;
        }
      } else if (modal.value.ruleType === 'geoip') {
        if (modal.value.geoipPreset === '__custom__') {
          targetValue = modal.value.customTarget.trim();
        } else {
          targetValue = modal.value.geoipPreset;
        }
        targetType = 'ip';
        matchType = 'geoip';
        if (!targetValue) {
          showToast('请选择或输入 GeoIP 预设代码', 'error');
          return;
        }
      } else if (modal.value.ruleType === 'cidr') {
        targetValue = modal.value.target.trim();
        targetType = 'ip';
        matchType = 'cidr';
        if (!targetValue) {
          showToast('请输入 IP 或 CIDR 网段', 'error');
          return;
        }
      }

      const categoryValue = modal.value.categoryMode === 'new'
        ? (modal.value.newCategoryInput.trim() || '自定义代理')
        : modal.value.category;

      try {
        if (modal.value.isEdit) {
          const res = await fetch('/api/rules/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              old_target: modal.value.oldTarget,
              new_target: targetValue,
              new_match_type: matchType,
              new_action: modal.value.action,
              new_category: categoryValue,
              target_type: targetType
            })
          });
          const data = await res.json();
          if (data.success) {
            showToast(`已成功修改规则并写回 v2rayA: ${data.new_target}`);
            modal.value.show = false;
            fetchRules();
          } else {
            showToast(data.detail || '修改失败', 'error');
          }
        } else {
          const res = await fetch('/api/rules/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              target: targetValue,
              action: modal.value.action,
              match_type: matchType,
              target_type: targetType,
              category: categoryValue
            })
          });
          const data = await res.json();
          if (data.success) {
            showToast(`已成功写入 v2rayA: ${data.target}`);
            modal.value.show = false;
            fetchRules();
          } else {
            showToast(data.detail || '添加失败', 'error');
          }
        }
      } catch (e) {
        showToast('保存规则失败', 'error');
      }
    };

    const cycleRuleAction = async (rule) => {
      const actions = ['proxy', 'direct', 'block'];
      const nextAction = actions[(actions.indexOf(rule.action) + 1) % actions.length];
      try {
        const res = await fetch('/api/rules/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            old_target: rule.target,
            new_target: rule.target,
            new_match_type: rule.match_type,
            new_action: nextAction,
            new_category: rule.category,
            target_type: rule.target_type
          })
        });
        const data = await res.json();
        if (data.success) {
          rule.action = nextAction;
          showToast(`已将 ${rule.target} 切换为: ${nextAction.toUpperCase()}`);
        }
      } catch (e) {
        showToast('切换动作失败', 'error');
      }
    };

    const autoFixRules = async () => {
      try {
        const res = await fetch('/api/rules/auto-fix', { method: 'POST' });
        const data = await res.json();
        showToast(`⚡ 自动修复完成！去除了 ${data.modified_www_count} 处 www 前缀，清除了 ${data.cleaned_redundant_count} 处重复冗余`);
        fetchRules();
      } catch (e) {
        showToast('修复失败', 'error');
      }
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
          showToast(`已成功写入 v2rayA: ${domain}`);
          fetchRules();
        }
      } catch (e) {
        showToast('添加规则失败', 'error');
      }
    };

    const deleteRule = async (target) => {
      if (!confirm(`确定要从 v2rayA 中删除规则 ${target} 吗？`)) return;
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

    const triggerReload = async () => {
      try {
        const res = await fetch('/api/v2ray/reload', { method: 'POST' });
        const data = await res.json();
        showToast(data.message || '已成功通知 v2rayA 重载内核生效！');
      } catch (e) {
        showToast('重载请求已发送');
      }
    };

    const syncFromV2rayA = async () => {
      try {
        const res = await fetch('/api/rules/sync', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
          showToast('已成功从 v2rayA 数据库同步最新配置！');
          fetchRules();
        } else {
          showToast(data.message || '未在数据库中检测到变更，已保留现有规则');
        }
      } catch (e) {
        showToast('同步失败', 'error');
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

    const handleVisibilityChange = () => {
      if (!document.hidden && isAuthenticated.value) {
        fetchRules();
      }
    };

    onMounted(() => {
      checkAuthStatus();

      document.addEventListener('visibilitychange', handleVisibilityChange);
      window.addEventListener('focus', () => {
        if (isAuthenticated.value) fetchRules();
      });

      timerInterval = setInterval(() => {
        if (monitorStatus.value.is_running) {
          monitorStatus.value.elapsed_seconds += 1;
        }
      }, 1000);
    });

    onUnmounted(() => {
      if (ws) ws.close();
      if (timerInterval) clearInterval(timerInterval);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', fetchRules);
    });

    return {
      authRequired,
      isAuthenticated,
      authChecked,
      loginPassword,
      loginError,
      isLoggingIn,
      showPassword,
      handleLogin,
      handleLogout,
      currentTab,
      targetIp,
      lanDevices,
      monitorStatus,
      alerts,
      storageInfo,
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
      ruleAudit,
      modal,
      toast,
      availableCategories,
      geositePresets: GEOSITE_PRESETS,
      geoipPresets: GEOIP_PRESETS,
      setModalRuleType,
      onGeositePresetChange,
      onGeoipPresetChange,
      toggleCategoryMode,
      onCategorySelectChange,
      getRuleBadge,
      getRuleFooter,
      openAddModal,
      openEditModal,
      onModalTargetInput,
      submitModal,
      cycleRuleAction,
      autoFixRules,
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
      triggerReload,
      syncFromV2rayA,
      formatTime
    };
  }
}).mount('#app');
