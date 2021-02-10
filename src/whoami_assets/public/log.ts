export function makeLog(loggerName: string) {
  return (level: "debug" | "info" | "error" | "warn", ...loggables: any[]) => {
    let message = [`[${loggerName}]`, ...loggables];
    if (typeof console[level] === "function") {
      console[level](...message);
    } else {
      console.log(`[${level}]`, ...message);
    }
  };
}
