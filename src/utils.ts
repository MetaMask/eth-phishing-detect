import { Config } from "./types";

export const serializeConfig = (config: Config): string => {
    return JSON.stringify(config, undefined, 2) + "\n";
}