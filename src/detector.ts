import { PhishingDetector as MetaMaskPhishingDetector, PhishingDetectorResult } from "@metamask/phishing-controller";

export default class PhishingDetector extends MetaMaskPhishingDetector {
    public check(hostname: string): PhishingDetectorResult {
        return super.check(`https://${hostname}`);
    }
}
