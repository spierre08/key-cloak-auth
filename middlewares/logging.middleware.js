import morgan from "morgan";
import chalk from "chalk";
import { v4 as uuidv4 } from "uuid";

morgan.token("datetime", () => {
  const now = new Date();
  const date = now.toLocaleDateString();
  const time = now.toLocaleTimeString();
  return `${date} ${time}`;
});

morgan.token("colored-method", (req, res) => {
  switch (req.method) {
    case "GET":
      return chalk.green(req.method);
    case "POST":
      return chalk.blue(req.method);
    case "PATCH":
      return chalk.yellow(req.method);
    case "DELETE":
      return chalk.red(req.method);
    default:
      return chalk.white(req.method);
  }
});

morgan.token("status-icon", (req, res) => {
  const status = res.statusCode;

  switch (status) {
    case 200:
      return chalk.green(`🟢 ${status}`);
    case 201:
      return chalk.green(`✅ ${status}`);
    case 204:
      return chalk.cyan(`🟢 ${status}`);
    case 400:
      return chalk.yellow(`😡 ${status}`);
    case 401:
      return chalk.magenta(`⚠️ ${status}`);
    case 403:
      return chalk.redBright(`⛔ ${status}`);
    case 404:
      return chalk.hex("#FFA500")(`❓ ${status}`);
    case 409:
      return chalk.hex("#800080")(`🔒 ${status}`);
    case 500:
      return chalk.red(`💥 ${status}`);
    default:
      if (status >= 500) return chalk.red(`💥 ${status}`);
      if (status >= 400) return chalk.yellow(`⚠️ ${status}`);
      if (status >= 300) return chalk.cyan(`🧩 ${status}`);
      if (status >= 200) return chalk.green(`✅ ${status}`);
      return chalk.white(status);
  }
});

export const MorganMiddleware = morgan(
  `${chalk.hex("#800080")(uuidv4())} - :datetime :colored-method :url :status-icon :response-time ms`,
);
