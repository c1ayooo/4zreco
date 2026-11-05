import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// 文档标题与描述是公网未鉴权即可抓到的指纹面（根路径 / 404 页都会带）。
// 用户裁定（2026-11-04）：标题直接用产品名；描述保持中性一句话。
export const APP_CONFIG = {
  name: "4zreco",
  version: packageJson.version,
  copyright: `© ${currentYear}, 4zreco (4zreco).`,
  meta: {
    title: "4zreco",
    description: "Authorized operations console",
  },
};
