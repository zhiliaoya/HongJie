Page({
  data: {
    resultTitle: '',
    resultDesc: ''
  },

  onLoad(options) {
    // 显式解码参数，避免乱码
    const title = options.title ? decodeURIComponent(options.title) : '操作完成';
    const desc = options.desc ? decodeURIComponent(options.desc) : '';
    
    this.setData({
      resultTitle: title,
      resultDesc: desc
    });
  },

  closeMiniProgram() {
    wx.exitMiniProgram();
  }
});