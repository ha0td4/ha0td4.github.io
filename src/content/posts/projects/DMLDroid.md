---
title: "DMLDroid: Deep Multimodal Fusion Framework for Android Malware Detection with Resilience to Code Obfuscation and Adversarial Perturbations"
published: 2025-01-28
description: ''
image: ''
tags: [Android, Malware, Deep Learning, Multomodal]
category: 'Projects'
draft: false 
lang: ''
---

Android malware poses a significant threat to mobile security, with attackers constantly evolving their techniques to evade detection. Traditional single-modality approaches often struggle to capture the diverse characteristics of malicious applications.

Below is an explanation of a multimodal approach for detecting Android malware using Deep Learning (DL). The framework utilizes feature fusion across three individual branches: Deep Neural Networks (DNN), Convolutional Neural Networks (CNN), and Bidirectional Encoder Representations from Transformers (BERT). Each branch processes different aspects of APK (Android Package Kit) files, and the outputs are combined in to improve predictive accuracy.

# Overview the framework

![DMLDroid framework](/assets/images/posts/DMLDroid/01.png)

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

The outputs from the three branches (each 128-dimensional on last hidden layer, or 1-dimesional on logit layer) are fused to create a comprehensive representation of the APK file. The fusion process combines features from all modalities to improve prediction performance.
There are many fusion strategy, but mainly I've done it on intermediately fusion:
- Concatenation of the three feature vectors (DNN, CNN, and BERT outputs).
- Attention mechanisms to emphasize critical features.
- Gated-fusion mechianism to utilize various information seamlessly for auto-adjusting prediction on each models.

# Experimental Results

Below is a comparison table of the models. While binary classification only cares whether the application is malicious or not, multi-class classification gives a deeper insight into the family of malware.

## Environment

My models were trained on Kaggle, with CPU Intel(R) Xeon(R) CPU @ 2.20GHz, 13 GB RAM, GPU Tesla P100-PCIE-16GB; Python 3.9, PyTorch 1.9.

## Classification Report

| Model                        | Acc.  | Rec.  | Pre.  | F1    | Training time (mins) | Testing time (mins) |
|------------------------------|-------|-------|-------|-------|----------------------|---------------------|
| DNN                          | 96.88 | 95.97 | 95.56 | 95.77 | 0.62                 | 0.10                |
| CNN                          | 95.15 | 93.90 | 93.01 | 93.44 | 1.55                 | 0.21                |
| BERT                         | 87.18 | 80.75 | 83.18 | 81.85 | 181.62               | 35.89               |
| Multimodal (concatenation)   | 97.72 | 96.81 | 96.97 | 96.89 | 179.60               | 34.15               |
| Multimodal (attention)       | 97.70 | 95.89 | 97.80 | 96.80 | 181.66               | 35.03               |
| Multimodal (gated-fusion)    | 97.44 | 96.71 | 96.34 | 96.52 | 180.89               | 34.76               |

- DNN performs well with all high evaluation metrics. It is also the fastest in terms of training (0.62 mins) and testing (0.10 mins).
- CNN has slightly lower performance compared to DNN, with accuracy and F1 scores around 95%. It is slower than DNN but still relatively efficient.
- BERT underperforms compared to DNN and CNN, with all evaluation metrics around 80-90%. It is significantly slower in both training (181.62 mins) and testing (35.89 mins), likely due to its complex architecture and large number of parameters.
- All multimodal methods (concatenation, attention, and gated fusion) outperform single-modality models (DNN, CNN, BERT) in all of evaluation metrics (all above 97%).

# Conclusion

We explored a multimodal approach for detecting Android malware using deep learning feature fusion. By integrating three distinct branches—DNN, CNN, and BERT—we were able to leverage complementary features extracted from Android APK files. 

For those interested in experimenting with the framework, the Kaggle notebook [AndMalMultimodal](https://www.kaggle.com/code/haotienducanh/andmalmultimodal) provides a practical starting point. Feel free to explore, modify, and build upon this work to advance the field of Android malware detection.
