Page({
  data: {
    sceneToken: '',
    loading: false,
    hasScene: false    // 是否扫码进入
  },

  onLoad(options) {
    console.log('页面加载，options:', options);

    let scene = '';
    if (options.scene) {
      scene = decodeURIComponent(options.scene);
      console.log('扫码小程序二维码值:', scene);
    } else if (options.q) {
      scene = decodeURIComponent(options.q);
      console.log('二维码参数:', scene);
    }

    if (scene) {
      // 扫码进入 → 显示授权确认页
      this.setData({ 
        sceneToken: scene,
        hasScene: true
      });
    } else {
      // 非扫码进入（搜索/历史记录） → 显示功能介绍页
      this.setData({ 
        hasScene: false
      });
    }

    console.log('场景令牌:', this.data.sceneToken);
    console.log('hasScene:', this.data.hasScene);
  },

  confirmLogin() {
    this.handleDynamicAction('confirm');
  },

  cancelLogin() {
    this.handleDynamicAction('cancel');
  },

  /**
   * 跳转到结果页
   */
  navigateToEnd(title, desc, delay = 1500) {
    setTimeout(() => {
      wx.redirectTo({
        url: `/pages/end/end?title=${encodeURIComponent(title)}&desc=${encodeURIComponent(desc)}`
      });
    }, delay);
  },

  /**
   * 处理动态链路确认（新版核心逻辑）
   */
  handleDynamicAction(action) {
    if (this.data.loading) return;

    const { sceneToken } = this.data;
    if (!sceneToken) {
      this.navigateToEnd('参数错误', '未获取到有效的场景令牌');
      return;
    }

    if (action === 'confirm') {
      this.loginWithWechatCode();
    } else if (action === 'cancel') {
      this.handleCancelDynamicAction();
    }
  },

  /**
   * 取消动态链路（通知后端作废该链路）
   */
  handleCancelDynamicAction() {
    const { sceneToken } = this.data;

    this.setData({ loading: true });

    wx.request({
      url: `你的域名地址/api/${sceneToken}`,
      method: 'POST',
      header: {
        'content-type': 'application/json'
      },
      data: {
        action: 'cancel'
      },
      success: (res) => {
        console.log('取消请求结果:', res);
        this.navigateToEnd('操作取消', '已取消登录，可手动关闭小程序');
      },
      fail: (err) => {
        console.error('取消请求失败:', err);
        this.navigateToEnd('操作取消', '已取消登录（链路将自动过期）');
      }
    });
  },

  /**
   * 通过微信 code 完成登录（核心流程）
   */
  loginWithWechatCode() {
    const { sceneToken } = this.data;

    this.setData({ loading: true });

    console.log('开始获取微信 code...');

    wx.login({
      success: (loginRes) => {
        if (!loginRes.code) {
          console.error('wx.login 失败：未获取到 code');
          this.setData({ loading: false });
          this.navigateToEnd('登录失败', '获取微信授权失败，请重试');
          return;
        }

        const code = loginRes.code;
        console.log('获取到微信 code:', code);

        this.verifyWithCode(sceneToken, code);
      },
      fail: (err) => {
        console.error('wx.login 调用失败:', err);
        this.setData({ loading: false });
        this.navigateToEnd('登录失败', '微信登录接口调用失败');
      }
    });
  },

  /**
   * 使用 code 访问动态链路进行验证
   */
  verifyWithCode(sceneToken, code) {
    console.log('开始验证:', {
      url: `你的域名地址/api/${sceneToken}`,
      code: code
    });

    wx.request({
      url: `你的域名地址/api/${sceneToken}`,
      method: 'POST',
      header: {
        'content-type': 'application/json'
      },
      data: {
        code: code
      },
      success: (res) => {
        console.log('验证结果:', res);

        if (res.statusCode === 200 && res.data && res.data.success) {
          this.navigateToEnd('登录成功', '已完成授权，可返回网页端继续操作');
        } else {
          const errorMsg = (res.data && res.data.message) || '验证失败';
          console.error('验证失败:', errorMsg);
          this.setData({ loading: false });
          this.navigateToEnd('登录失败', errorMsg);
        }
      },
      fail: (err) => {
        console.error('验证请求失败:', err);
        this.setData({ loading: false });
        this.navigateToEnd('登录失败', '网络错误，请重试');
      }
    });
  }
});
