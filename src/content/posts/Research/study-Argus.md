---
title: A Deep Dive into Fileless Malware Detection
published: 2025-03-12
description: ''
image: ''
tags: [Malware, Detection, Memory Analysis, Deep Learning, MITRE ATT&CK]
category: 'Research'
draft: false
lang: ''
---

<!-- markdownlint-disable MD013 -->

Traditional antivirus solutions struggle against a new breed of cyber threats: **Fileless malware**, which operates entirely in system memory, leaving no trace on disk. These attacks bypass conventional detection methods, making them one of the most dangerous challenges in cybersecurity today.
Facing this challenge, **Argus**, an advanced early-stage fileless malware detection system leveraging deep learning and the MITRE ATT&CK framework to identify threats before they escalate. By analyzing memory snapshots in real time, Argus can detect malicious activity in its pre-operational phase, preventing devastating data breaches.
The proposed Argus system for early-stage fileless malware detection consists of two key architectural components: the `Feature Explainer` and the `Early-Stage Detector`. Its operational workflow involves these two phases working in tandem.

# 1. Feature Explainer

![Feature Explainer](/src/assets/images/posts/study-argus/01.png)

- **Monitoring for Suspicious Processes**: Argus continuously monitors the system in real-time for suspicious processes using `Windows Management Instrumentation (WMI)`. It looks for unusual process names, high resource usage, and unusual network activity.
- **Queueing Suspicious Processes**: When a suspicious process is identified, its Process ID (PID) is appended to a queue for further analysis.
- **Capturing Memory Snapshots**: A suspicious process PID is dequeued and Argus automatically invokes the ProcDump command-line utility to capture a memory snapshot of the process.
- **Extracting Key Features**: Custom plugins developed using Volatility documentation are used to extract key features from the acquired memory snapshot. These raw features include:
  - **Parent-Child Process Relationships**: Detecting abnormal relationships such as a script executed by an unexpected parent process via mshta.exe.
  - **Tracing Execution Paths**: Identifying deviations from standard execution paths, like `c:\Windows\syswow64\dllhost.exe` being used for malicious activity.
  - **Monitoring Sensitive Registry Keys**: Detecting unauthorized modifications to registry keys for persistence or evasion.
  - **Identifying Code Injection Attempts**: Recognizing attempts to inject malicious code into legitimate processes.
  - **Recognizing Signs of Process Hollowing**: Identifying processes that appear legitimate but are executing malicious code.
  - **Suspicious Network Activity**: Detecting anomalous network connections initiated by a process, potentially indicating communication with C2 servers.

![regex patterns](/src/assets/images/posts/study-argus/02.png)

- **Generating Explained Features**: The extracted key features are then fed into a fine-tuned Llama model (feature explainer model) to generate explained features corresponding to those key features. This model is fine-tuned on a Feature explanation dataset created from behavioral reports, as shown below:
![image](/src/assets/images/posts/study-argus/03.png)
Here is a structure of Llama feature explainer model:
![image](/src/assets/images/posts/study-argus/04.png)

# 2. Early-Stage Detector

![image](/src/assets/images/posts/study-argus/05.png)

- **MITRE-attack-dataset**: This component utilizes a MITRE-attack-dataset, which is prepared from the MITRE ATT&CK enterprise matrix. This dataset contains information on adversary tactics and techniques based on real-world observations.
![image](/src/assets/images/posts/study-argus/06.png)

- **Correlation and Detection**: The generated explained features from the [Feature Explainer](#1-Feature-Explainer) are correlated with the MITRE-attack-dataset.
- **Fine-tuned BERT Model with MLP**: An early-stage detector is a fine-tuned BERT (Bidirectional Encoder Representations from Transformers) model combined with an MLP (Multilayer Perceptron), is used to identify fileless malware attacks at an early stage. The BERT model is fine-tuned on the MITRE-attack-dataset.

# 3. Operational Workflow

1. Argus continuously monitors the system for suspicious processes using WMI.
2. When a suspicious process is found, its PID is added to a queue.
3. Argus dequeues a PID and uses ProcDump to capture a memory snapshot.
4. Custom plugins extract key features from the memory snapshot.
5. The extracted features are fed to the fine-tuned Llama model to generate explained features.
6. These explained features are then correlated with the MITRE ATT&CK framework using a fine-tuned BERT model with an MLP to detect fileless malware at an early stage.
7. Argus can then identify the active stage of the fileless malware attack based on the correlation with the MITRE ATT&CK tactics.

Argus aims to detect fileless malware before its operational stage to prevent potential damage and data breaches. The experimental results showed that Argus could successfully identify fileless malware samples in both the pre-operational and operational phases.

# 4. Experimental Result

## 4.1. Argus performance on benchmark dataset

The performance of Argus evaluated across various APT threat groups. Notably, Argus did not detect any threats at the initial stage since it relies on memory analysis, which occurs after the malware has achieved initial access. Finally, Argus detected 2978 samples (out of total 5026 samples) at the pre-operation stage, 1889 samples at the subsequent stages, and 59 samples failed to detect. These results indicate that Argus is most effective in detecting fileless malware at the *pre-operation stage*.
![image](/src/assets/images/posts/study-argus/07.png)

## 4.2. Argus performance comparison with existing SOTA

Argus demonstrated robust performance by identifying 2978 fileless malware samples at the Pre-operational stage and 1378 samples at the Operational stage. The results demonstrate Argus efficiency in detecting fileless malware attacks at an early stage and outperform existing state-of-the-art methods with an impressive detection accuracy of 96.84%.
![image](/src/assets/images/posts/study-argus/08.png)

## 4.3. Computational performance comparison

The performance evaluation is conducted by selecting 1000 random processes of each different size. The analysis is focused on determining the average time taken by feature generation and early-stage detection for each memory dump. In conclusion, Argus outperforms existing SOTA, which takes 11.252s to analyse smaller processes and 136.343s to analyse larger processes.
![image](/src/assets/images/posts/study-argus/09.png)

# 5. Reference

Kara, I. (2023). Fileless malware threats: Recent advances, analysis approach through memory forensics and research challenges. Expert Systems with Applications, 214, 119133.
