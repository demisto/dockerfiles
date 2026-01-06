import struct
import numpy as np
import lightgbm as lgbm

MODELS_FEATURE_COUNT = {"JS": 9355, "VBS": 707, "PS": 26143}


def convert_binary_fv_to_python_fv(data, num_features, sample_id=""):
    """
    Convert binary feature vector to Python numpy array.

    Args:
        data: Binary data containing sparse feature vector
        num_features: Total number of features in the model
        sample_id: Optional identifier for error messages

    Returns:
        numpy array of shape (num_features,) with feature values
    """
    if len(data) == 0:
        raise Exception(f"{sample_id}: Empty feature vector")

    fv = np.zeros(num_features)
    feature_size = struct.calcsize("Qd")  # Unsigned long long (8 bytes) + double (8 bytes)

    if len(data) % feature_size != 0:
        raise ValueError(f"{sample_id}: Invalid size")

    num_nonzero_features = len(data) // feature_size
    for i in range(num_nonzero_features):
        feature_idx, feature_val = struct.unpack("Qd", data[i * feature_size : (i + 1) * feature_size])
        fv[feature_idx] = feature_val

    return fv


def main():
    """
    Main function to loop through all models, load them, and generate predictions.
    """
    for model_name, feature_count in MODELS_FEATURE_COUNT.items():
        print(f"\n{'='*60}")
        print(f"Processing {model_name} model")
        print(f"{'='*60}")

        # Construct file paths
        model_path = f"{model_name}/model.txt"
        sample_fv_path = f"{model_name}/sample_fv.bin"

        try:
            # Load the LightGBM model
            print(f"Loading model from: {model_path}")
            booster = lgbm.Booster(model_file=model_path)

            # Read the binary feature vector
            print(f"Reading feature vector from: {sample_fv_path}")
            with open(sample_fv_path, "rb") as f:
                binary_data = f.read()

            # Convert binary feature vector to Python numpy array
            print(f"Converting feature vector (expected {feature_count} features)")
            fv = convert_binary_fv_to_python_fv(
                binary_data,
                feature_count,
            )

            # Generate prediction
            print(f"Generating prediction...")
            prediction = booster.predict(fv.reshape(1, -1))

            # Print results
            print(f"\n{model_name} Model Results:")
            print(f"  Feature vector shape: {fv.shape}")
            print(f"  Prediction score: {prediction[0]:.6f}")

        except FileNotFoundError as e:
            print(f"ERROR: File not found - {e}")
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")

    print(f"\n{'='*60}")
    print("All models processed")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
