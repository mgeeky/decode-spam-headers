import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const legacyConfigPath = path.join(__dirname, ".eslintrc.json");
const legacyConfig = JSON.parse(fs.readFileSync(legacyConfigPath, "utf8"));

const compat = new FlatCompat({ baseDirectory: __dirname });

export default compat.config(legacyConfig);
