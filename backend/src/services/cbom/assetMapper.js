function toApiAsset(asset) {
  return {
    ...asset,
    asset_id: asset.assetId,
    asset_type: asset.assetType,
    key_length: asset.keyLength,
    hash_algorithm: asset.hashAlgorithm,
    system_name: asset.systemName,
    owner_team: asset.ownerTeam,
    expiry_date: asset.expiryDate,
    days_to_expiry: asset.daysToExpiry,
    last_rotated: asset.lastRotated,
    rotation_policy: asset.rotationPolicy,
    quantum_safe: asset.quantumSafe,
    risk_rating: asset.riskRating,
    updated_at: asset.updatedAt,
    created_at: asset.createdAt
  };
}

function toPrismaUpsertPayload(asset) {
  const expiryDate = asset.expiry_date ? new Date(asset.expiry_date) : null;
  const lastRotated = asset.last_rotated ? new Date(asset.last_rotated) : null;

  return {
    where: { assetId: asset.asset_id },
    update: {
      algorithm: asset.algorithm,
      keyLength: asset.key_length,
      expiryDate,
      daysToExpiry: asset.days_to_expiry,
      quantumSafe: asset.quantum_safe,
      riskRating: asset.risk_rating,
      issues: asset.issues,
      updatedAt: new Date()
    },
    create: {
      assetId: asset.asset_id,
      assetType: asset.asset_type,
      algorithm: asset.algorithm,
      keyLength: asset.key_length,
      hashAlgorithm: asset.hash_algorithm,
      systemName: asset.system_name,
      environment: asset.environment,
      ownerTeam: asset.owner_team,
      issuer: asset.issuer,
      expiryDate,
      daysToExpiry: asset.days_to_expiry,
      lastRotated,
      rotationPolicy: asset.rotation_policy,
      quantumSafe: asset.quantum_safe,
      riskRating: asset.risk_rating,
      issues: asset.issues,
      notes: asset.notes,
      updatedAt: new Date()
    }
  };
}

module.exports = {
  toApiAsset,
  toPrismaUpsertPayload
};
