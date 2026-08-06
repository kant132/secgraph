"""真实 webgoat 漏洞 nodeid — 由 gen_test_data.py 生成。每类最多 2 个。"""

VULN_NODEIDS = [
    "method:b65c34a1b3d7210b903677b63751332f",   # Deser | InsecureDeserializationTask::completed
    "method:6fb7ade8fb232550e8a47808c726f0c3",    # Path  | ProfileUploadBase::cleanupAndCreateDirectoryForUser
    "method:90b5f008f2652be8bcadf19399278212",    # Path  | ProfileUploadBase::getProfilePictureAsBase64
    "method:647d162fdf923cdfbc8d4343d418e51e",    # SQLi  | SqlInjectionChallenge::registerNewUser
    "method:18ca1fb7e0e51da322bd53075fc76719",    # SQLi  | SqlInjectionChallengeLogin::login
]
