# CyberScan Synthetic Dataset Audit - Phase B

## Executive Summary
The synthetic dataset contains **trivial shortcuts** that allow simple baselines to achieve 100% accuracy. Feature 3025 (byte histogram) perfectly separates classes because each family uses a unique repeated byte value. This violates the intended security evaluation purpose.

## Critical Findings

### 1. Trivial Feature Leakage
- **Feature 3025** (byte histogram index) shows perfect class separation
- Each family uses a unique byte value repeated throughout the file:
  - clean families: bytes 17, 34, 51, 68, 85, 102, 119, 136, 153, 170
  - suspicious families: bytes 124, 155, 186, 217, 248
  - malware families: bytes 47, 77, 90, 204, 141, 188, 235, 214
- Decision tree using ONLY this feature achieves **100% accuracy**

### 2. Within-Family Variation Issues
- Families contain 3 samples but are not identical
- Some samples within same family differ by only 8-14 features (out of 4096)
- This creates **intra-class confusion** that shouldn't exist in a clean benchmark

### 3. Baseline Performance Reveals Flaws
| Model | Seed 42 | Seed 456 | Seed 999 |
|-------|---------|---------|---------|
| Majority Vote | 0% | 14% | 0% |
| Decision Tree | 100% | 100% | 100% |
| RF Classifier | 100% | 100% | 33% |
| Structural Classifier | 100% | 100% | 100% |

## Impact Analysis
- **Security Evaluation Invalid**: The dataset tests memorization of byte patterns, not structural analysis
- **Model Generalization Unproven**: High accuracy comes from exploiting dataset construction, not learning meaningful features
- **Real-World Irrelevance**: No protection against actual malware detection techniques

## Recommendations
1. **Regenerate synthetic dataset** with diverse, realistic patterns per class
2. **Remove deterministic byte-level shortcuts** - use random bytes
3. **Add legitimate structural variation** within each class
4. **Document limitations** in README and model metadata

## Next Steps
- Implement improved synthetic dataset generator
- Re-run full pipeline with new dataset
- Compare baseline vs. classifier performance
- Document statistical properties and limitations
