---
title: Multimodal Android Malware Detection Using Deep Learning Feature Fusion
published: 2025-01-28
description: ''
image: ''
tags: [Android Malware, Deep Learning, Multomodal]
category: 'Project'
draft: false 
lang: ''
---

Android malware poses a significant threat to mobile security, with attackers constantly evolving their techniques to evade detection. Traditional single-modality approaches often struggle to capture the diverse characteristics of malicious applications.

Below is an explanation of a multimodal approach for detecting Android malware using Deep Learning (DL). The framework utilizes feature fusion across three individual branches: Deep Neural Networks (DNN), Convolutional Neural Networks (CNN), and Bidirectional Encoder Representations from Transformers (BERT). Each branch processes different aspects of APK (Android Package Kit) files, and the outputs are combined in to improve predictive accuracy.

# Overview the framework

![image](https://hackmd.io/_uploads/SJoLGySd1l.png)

My research multimodal framework integrates complementary features extracted from Android APK files using three separate branches:

- DNN Branch: Extracts and analyzes tabular features such as permissions, intents, and other metadata from AndroidManifest files.
- CNN Branch: Processes APK DEX files by converting them into RGB images to capture structural patterns.
- BERT Branch: Analyzes API call sequences generated from the APK's call graphs using a pre-trained BERT model.

Each branch outputs a 128-dimensional feature vector and a logit prediction vector that are fused for final malware prediction.

# Branch-Specific Processing

## 1. DNN Branch: Tabular Feature Analysis

The DNN branch processes tabular data extracted from the AndroidManifest.xml file, which is retireved by Apktool, including permissions, intents, services, and other metadata. These features are crucial for understanding the behavior and capabilities of an Android application.
The input of this branch is a 1D vector of size 400, representing the tabular features.
A DNN with fully connected layers is used to analyze the tabular data. The network learns to identify patterns and relationships in the metadata that may indicate malicious behavior.

## 2. CNN Branch: Image-Based Bytecode Analysis
The CNN branch focuses on the DEX (Dalvik Executable) files within the APK, which is extracted by decompressor like 7-zip, tar. These files contain the bytecode of the application, which is converted into RGB images. This transformation allows the CNN to analyze structural patterns in the bytecode that may be indicative of malware.
The input is a 3-channel RGB image with dimensions (3, 64, 64), where 3 represents the color channels and 64x64 is the spatial resolution of the image.
A CNN is employed to extract spatial features from the bytecode images. The CNN uses convolutional layers to detect local patterns and hierarchical structures in the image data.

## 3. BERT Branch: API Call Sequence Analysis
The BERT branch processes sequences of API calls generated from the APK's call graphs (which is extracted using Androguard). These sequences represent the dynamic behavior of the application and provide insights into how the app interacts with the Android system.
The input consists of two components: input_ids (tokenized API call sequences) and attention_mask (to handle variable sequence lengths). These are standard inputs for transformer-based models like BERT.
A pre-trained DistilBERT model is fine-tuned on the API call sequences. DistilBERT is a lightweight version of BERT that retains much of its performance while being more computationally efficient. The model learns to understand the semantic relationships between API calls and their potential malicious intent.

## Summary of each branches

| Branch | Input data | Input shape | Architecture | Extractor
| ------ | ---------- | ----------- | ------------ | --------
| **DNN** - Tabular Feature Analysis | Tabular data of permissions, actions, services | (400,) | A deep neural network with fully connected layers | Apktool 
| **CNN** - Image-Based Bytecode Analysis | Bytecode extracted from the DEX file, converted into RGB image | (3, 64, 64) | A convolutional neural network extracts spatial patterns | Decompressor (7-zip, tar, ...)
| **BERT** - API Call Sequence Analysis | API call graphs are converted into sequences of API calls | (input_ids, attention_mask) | A pre-trained DistilBERT model fine-tuned on API call sequences | Androguard

# Feature Fusion

The outputs from the three branches (each 128-dimensional on last hidden layer, or 1/5 dimesional on logit layer) are fused to create a comprehensive representation of the APK file. The fusion process combines features from all modalities to improve prediction performance.
There are many fusion strategy, but mainly I've done it on early-fusion and late-fusion:

## Early-fusion

- Concatenation of the three feature vectors (DNN, CNN, and BERT outputs).
- Attention mechanisms to emphasize critical features.
- Gated-fusion mechianism to utilize various information seamlessly for auto-adjusting prediction on each models.

## Late-fusion

- Predictions from the individual branches are combined using methods such as weighted averaging, ensemble learning, or majority voting.

# Experimental Results

Below is a comparison table of the models. While binary classification only cares whether the application is malicious or not, multi-class classification gives a deeper insight into the family of malware.

## Environment

My models were trained on Kaggle, with CPU Intel(R) Xeon(R) CPU @ 2.20GHz, 13 GB RAM, GPU Tesla P100-PCIE-16GB; Python 3.9, PyTorch 1.9.

## Binary Classification

| Model                        | Acc.  | Rec.  | Pre.  | F1    | Training time (mins) | Testing time (mins) |
|------------------------------|-------|-------|-------|-------|----------------------|---------------------|
| DNN                          | 96.88 | 96.88 | 96.90 | 96.89 | 0.62                 | 0.10                |
| CNN                          | 95.15 | 95.15 | 95.21 | 95.17 | 1.55                 | 0.21                |
| BERT                         | 87.18 | 87.18 | 86.83 | 86.94 | 181.62               | 35.89               |
| Multimodal (concatenation)   | 98.16 | 98.16 | 98.16 | 98.16 | 318.20               | 53.40               |
| Multimodal (attention)       | 98.30 | 98.30 | 98.30 | 98.30 | 315.17               | 52.20               |
| Multimodal (gated-fusion)    | 97.96 | 97.96 | 97.96 | 97.96 | 180.54               | 35.08               |

DNN performs well with high accuracy (96.88%), precision (96.90%), recall (96.88%), and F1 score (96.89%). It is also the fastest in terms of training (0.62 mins) and testing (0.10 mins).

CNN has slightly lower performance compared to DNN, with accuracy and F1 scores around 95%. It is slower than DNN but still relatively efficient.

BERT underperforms compared to DNN and CNN, with accuracy and F1 scores around 87%. It is significantly slower in both training (181.62 mins) and testing (35.89 mins), likely due to its complex architecture and large number of parameters.

All multimodal methods (concatenation, attention, and gated fusion) outperform single-modality models (DNN, CNN, BERT) in terms of accuracy, precision, recall, and F1 score (all above 97%).

Multimodal (attention) achieves the highest performance (98.30% accuracy and F1 score), but it requires the longest training time (315.17 mins).

Multimodal (gated fusion) strikes a balance between performance (97.96% accuracy and F1 score) and efficiency, with significantly lower training time (180.54 mins) compared to concatenation and attention-based methods.

## Multi-class Classification

| Model                        | Acc.  | Rec.  | Pre.  | F1    | Training time (mins) | Testing time (mins) |
|------------------------------|-------|-------|-------|-------|----------------------|---------------------|
| DNN                          | 91.95 | 91.27 | 89.64 | 90.08 | 0.60                 | 0.10                |
| CNN                          | 86.68 | 84.32 | 83.98 | 84.14 | 1.55                 | 0.21                |
| BERT                         | 76.98 | 72.24 | 72.87 | 72.37 | 178.58               | 34.50               |
| Multimodal (concatenation)   | 95.67 | 94.63 | 95.50 | 95.04 | 314.30               | 51.80               |
| Multimodal (attention)       | 95.55 | 95.55 | 95.54 | 95.54 | 314.60               | 51.42               |
| Multimodal (gated-fusion)    | 95.53 | 95.53 | 95.56 | 95.52 | 184.97               | 37.18               |

DNN performs well again, with accuracy (91.95%) and F1 score (90.08%). It remains the fastest model in terms of training and testing times.

CNN shows a noticeable drop in performance compared to DNN, with accuracy (86.68%) and F1 score (84.14%). This suggests that CNNs may struggle more with multi-class tasks compared to binary classification.

BERT performs the worst among all models, with accuracy (76.98%) and F1 score (72.37%). Its poor performance might be due to the complexity of multi-class tasks and the lack of sufficient fine-tuning or data.

All multimodal methods achieve significantly higher performance compared to single-modality models, with accuracy and F1 scores above 95%.

Multimodal (concatenation) achieves the highest accuracy (95.67%) and F1 score (95.04%).

Multimodal (attention) and Multimodal (gated fusion) perform similarly, with slight differences in precision and recall.

Multimodal (gated fusion) is the most efficient among multimodal methods, with training time (184.97 mins) closer to BERT but much faster than concatenation and attention-based methods.

# Conclusion

We explored a multimodal approach for detecting Android malware using deep learning feature fusion. By integrating three distinct branches—Deep Neural Networks (DNN), Convolutional Neural Networks (CNN), and Bidirectional Encoder Representations from Transformers (BERT)—we were able to leverage complementary features extracted from Android APK files. 

For those interested in experimenting with the framework, the Kaggle notebook [AndMalMultimodal](https://www.kaggle.com/code/haotienducanh/andmalmultimodal/output?scriptVersionId=219451852) provides a practical starting point (btw, sorry for various versions, I can't delete failed version T.T). Feel free to explore, modify, and build upon this work to advance the field of Android malware detection.
