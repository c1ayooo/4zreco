import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// 文档标题与描述是公网未鉴权即可抓到的指纹面（根路径 / 404 页都会带）。
// 保持中性，产品名只出现在登录后界面（可见即已通过鉴权）。
export const APP_CONFIG = {
  name: "4zreco",
  version: packageJson.version,
  copyright: `© ${currentYear}, 4zreco (4zreco).`,
  meta: {
    title: "Console",
    description: "Authorized operations console",
  },
};
