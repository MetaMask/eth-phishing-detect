import { PhishingDetector } from "@metamask/phishing-controller";
import config from "./config.json";

const detector = new PhishingDetector(config);

export default function checkDomain(domain: string) {
    return detector.check(domain).result;
}
