title: "AndMalMultimodal: Multimodal machine learning for Android Malware detection"
date: 2024-09-01 14:40:34
categories: 
  - [Machine Learning]
tags:
  - ML
  - Android
  - malware detection
---
Link notebook: [DNN-CNN-BERT](https://www.kaggle.com/code/haotienducanh/dnn-cnn-bert)

Note: I use tiny-bert model [`gaunernst/bert-tiny-uncased`](https://huggingface.co/gaunernst/bert-tiny-uncased) to minimize computational resources

## Contents

- [Overview](#Overview)
- [Two-label multimodal classification report](#Two-label-multimodal)
- [Five-label multimodal classification report](#Five-label-multimodal)

## Overview

**Two-label multimodal**
![cfm](/assets/AndMalMultimodal/AndMalMultimodal-20240901-01.png)
![acc_compare](/assets/AndMalMultimodal/AndMalMultimodal-20240901-02.png)
![loss_compare](/assets/AndMalMultimodal/AndMalMultimodal-20240901-03.png)


**Five-label multimodal**

![cfm](/assets/AndMalMultimodal/AndMalMultimodal-20240901-04.png)
![acc_compare](/assets/AndMalMultimodal/AndMalMultimodal-20240901-05.png)
![loss_compare](/assets/AndMalMultimodal/AndMalMultimodal-20240901-06.png)

## Two-label multimodal

Self-attention

```cpp
Classification Report SA:
              precision    recall  f1-score   support

      Benign     0.9766    0.9728    0.9747       773
     Malware     0.9918    0.9930    0.9924      2565

    accuracy                         0.9883      3338
   macro avg     0.9842    0.9829    0.9836      3338
weighted avg     0.9883    0.9883    0.9883      3338              
```

Cross-attention

```cpp
Classification Report CA:
              precision    recall  f1-score   support

      Benign     0.9728    0.9702    0.9715       773
     Malware     0.9910    0.9918    0.9914      2565

    accuracy                         0.9868      3338
   macro avg     0.9819    0.9810    0.9815      3338
weighted avg     0.9868    0.9868    0.9868      3338
```

LSTM

```cpp
Classification Report LSTM:
              precision    recall  f1-score   support

      Benign     0.9829    0.9677    0.9752       773
     Malware     0.9903    0.9949    0.9926      2565

    accuracy                         0.9886      3338
   macro avg     0.9866    0.9813    0.9839      3338
weighted avg     0.9886    0.9886    0.9886      3338
```

## Five-label multimodal

Self-attention

```cpp
Classification Report SA:
              precision    recall  f1-score   support

      Adware     0.9360    0.9624    0.9490       319
     Banking     0.9582    0.9322    0.9450       516
      Benign     0.9706    0.9819    0.9762       773
    Riskware     0.9577    0.9565    0.9571       781
         SMS     0.9937    0.9905    0.9921       949

    accuracy                         0.9688      3338
   macro avg     0.9632    0.9647    0.9639      3338
weighted avg     0.9689    0.9688    0.9688      3338
```

Cross-attention

```cpp
Classification Report CA:
              precision    recall  f1-score   support

      Adware     0.9394    0.9718    0.9553       319
     Banking     0.9515    0.9496    0.9505       516
      Benign     0.9564    0.9922    0.9740       773
    Riskware     0.9812    0.9347    0.9574       781
         SMS     0.9926    0.9905    0.9916       949

    accuracy                         0.9697      3338
   macro avg     0.9642    0.9678    0.9658      3338
weighted avg     0.9701    0.9697    0.9697      3338

```

LSTM

```cpp
Classification Report LSTM:
              precision    recall  f1-score   support

      Adware     0.9120    0.9749    0.9424       319
     Banking     0.9699    0.9360    0.9527       516
      Benign     0.9682    0.9832    0.9756       773
    Riskware     0.9688    0.9539    0.9613       781
         SMS     0.9947    0.9905    0.9926       949

    accuracy                         0.9703      3338
   macro avg     0.9627    0.9677    0.9649      3338
weighted avg     0.9708    0.9703    0.9704      3338

```
