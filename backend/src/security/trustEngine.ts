interface TrustParams {
  failedAttempts: number;
  unusualLocation: boolean;
  newDevice: boolean;
  suspiciousTime: boolean;
}

export const calculateTrustScore = ({
  failedAttempts,
  unusualLocation,
  newDevice,
  suspiciousTime,
}: TrustParams): number => {
  let score = 100;

  score -= failedAttempts * 10;

  if (unusualLocation) score -= 20;
  if (newDevice) score -= 15;
  if (suspiciousTime) score -= 10;

  return Math.max(score, 0);
};