4zreco 图标包  |  基于 D 版字标（4-z-r-e-c-o + 闪电）

【目录】
svg/           矢量源文件，透明底
  - 4zreco-icon-dark.svg    深色字形，用于浅色背景
  - 4zreco-icon-light.svg   白色字形，用于深色背景
  - 4zreco-mark-dark.svg    简化标记（4 + 闪电），用于浅色背景
  - 4zreco-mark-light.svg   简化标记，用于深色背景
png/white/     白底 + 深色图标，不透明，16/32/48/64/96/128/152/180/192/256/512/1024
png/dark/      深底 + 白色图标，不透明，同上尺寸
png/mark/      简化标记，white/dark 两套，16/32/48/64
png/transparent/  透明底白色图标 512，用于叠加到自定义背景
favicon.ico    16 + 32 + 48，已用简化标记

【怎么用】
≥ 64px：用 png/white/ 或 png/dark/ 的完整字标
≤ 48px：用 png/mark/ 的简化标记（完整六字母在 48px 以下会糊成一条）
favicon / 浏览器标签 / 桌面快捷方式：直接用 favicon.ico
PWA / 需要透明底：用 svg/ 或 png/transparent/

【色值】
图标深色  #0B0D10
背景深色  #0B0D10
背景浅色  #FFFFFF

【注意】
16×16 是位图物理极限，简化标记在此尺寸只能保留轮廓感；若需要绝对清晰，
建议单独做一个纯「4」字符版本。所有 PNG 均由 SVG 渲染，缩放请以 svg/ 为准。
