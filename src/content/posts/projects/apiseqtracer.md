---
title: Behavior-Centric Malware Analysis Through Multi-Stage Processing and ATT&CK Correlation
published: 2025-12-28
description: ''
image: ''
tags: [Malware, MITRE, LLM, Agent]
category: 'Project'
draft: false 
lang: ''
---

In this project, malware analysis system is built on a three-layer architecture designed to move beyond basic detection into deep behavioral interpretation and MITRE ATT&CK mapping. Each layer operates independently but remains tightly integrated, enabling the pipeline to progress from raw execution signals to high-level threat intelligence. This structure allows not only classification of malicious samples, but also the extraction of behavioral insights that support investigation, threat hunting, and automated TTP (Tactics, Techniques, Procedures) identification.
![image](https://hackmd.io/_uploads/SkESTaXVbx.png)

# Dataset

To evaluate the system, we aggregated malware execution traces from multiple publicly available sources. Data was collected from:

- [r/datasets – Malware & Benign PE Cuckoo Reports](https://www.reddit.com/r/datasets/comments/exhy38/malware_and_benign_windows_pe_cuckoo_reports/): Provides Cuckoo sandbox execution logs for both malware and benign Windows binaries.
- [APIMDS](https://ocslab.hksecurity.net/apimds-dataset): A labeled malware dataset containing monitored API call sequences across various families.
- [MalbehavD-V1](https://github.com/mpasco/MalbehavD-V1): Focused on behavior-driven samples with process execution details suitable for dynamic analysis.

All samples were executed inside a controlled sandbox environment to extract API call sequences for downstream processing. The final dataset contains multiple malware families alongside benign executables, forming a diverse testbed for behavior-based threat analysis.

The label distribution is shown in the chart below:
![image](https://hackmd.io/_uploads/HJANkCXE-x.png)

As illustrated in the pie chart, Trojan samples dominate the dataset, followed by Miscellaneous, Adware, and Benign classes. This imbalance reflects common trends in real-world malware distributions and highlights the importance of balanced evaluation strategies.

## Layer 1 – Malware Detection

Execution traces are first collected through a sandbox environment, where each sample is analyzed and its API call sequence is recorded. These API calls are transformed into a fixed-length feature vector of 1143 dimensions, with each dimension representing the frequency of a corresponding API within the global API set. An ensemble model combining Random Forest and XGBoost is used to classify the sample as malicious or benign. In addition to classification probability, this layer produces an explainability report using SHAP values, highlighting the APIs that contributed most to the model decision. The detection component therefore acts as the primary filtering stage, providing a reliable base for deeper behavioral analysis in subsequent layers.

## Layer 2 – Behavioral Analysis

While Layer 1 focuses on classification, the second layer aims to capture and interpret behavioral patterns. The raw API sequence is first processed using a Log2-based noise reduction technique to eliminate redundant consecutive calls. The cleaned sequence is then segmented using a sliding-window approach to generate API gadgets—continuous execution fragments representing localized behaviors. Each gadget is encoded using CodeBERT to generate semantic embeddings, offering a richer contextual understanding compared to traditional discrete representations.

These embeddings are clustered using HDBSCAN, and clusters with valid labels (cluster_id ≠ -1) are retained as behaviorally meaningful groups with potential malicious indicators. In parallel, a bag-of-APIs model using TF-IDF is applied, and Sequential Pattern Mining with PrefixSpan combined with Discriminative Scoring is used to extract API patterns that distinguish malware families. This layer produces two critical outputs: suspicious gadget clusters with maliciousness likelihood, and characteristic sequential API patterns representing family-specific behaviors. Both serve as essential input for semantic interpretation and MITRE mapping.

## Layer 3 – MITRE ATT&CK Mapping

The final layer bridges behavioral signals with threat intelligence by translating them into ATT&CK-aligned interpretations. A Large Language Model (LLM Interpreter) is first used to convert API gadgets into natural-language behavioral descriptions—such as network communication, system manipulation, file operations, or registry modification. These descriptions are then processed by an Analysis Agent operating under a Retrieval-Augmented Generation (RAG) framework. The agent queries a MITRE knowledge base containing tactic-technique mappings, malware behavior references, and API-to-TTP correlation data.

Using semantic matching between system-generated behavior descriptions and retrieved MITRE knowledge, the system infers relevant attack techniques and tactics. The final output is an automatically generated report summarizing detected TTPs, reasoning context, and originating gadget evidence. As a result, the system evolves from simple malware detection into a comprehensive analytical engine that supports digital forensics, active attack monitoring, and strategic defense decision-making.

# Additional
You can explore the most APISeqTracer source code on GitLab: <https://gitlab.com/ha0td4/apiseqtracer>.