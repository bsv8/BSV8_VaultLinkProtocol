import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

// 优先使用显式路径；本机便携 Edge 只存放在项目工具目录，避免安装/修改日常浏览器。
const localEdge = fileURLToPath(
  new URL(
    "../../.tools/edge/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    import.meta.url,
  ),
);
export const browserChannel = process.env.VLP_BROWSER_CHANNEL ?? "msedge";
export const browserExecutable =
  process.env.VLP_BROWSER_EXECUTABLE ??
  (browserChannel === "msedge" && existsSync(localEdge)
    ? localEdge
    : undefined);
export const browserOptions = {
  channel: browserChannel,
  headless: true,
  ...(browserExecutable ? { executablePath: browserExecutable } : {}),
};
