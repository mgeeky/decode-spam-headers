export interface CaptchaChallengeData {
  challengeToken: string;
  imageBase64: string;
}

export interface CaptchaVerifyPayload {
  challengeToken: string;
  answer: string;
}

export interface CaptchaVerifyResponse {
  success: boolean;
  bypassToken?: string | null;
}
