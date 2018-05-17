# 857project

To run tests: 'python3 ./tests.py".  
* Requirements: phe, PyCrypto  
* Note: >2 clients requires 'multiclient' branch. This branch supports more than two clients at the cost of performance. This is because having more than two clients can lead to multiple client-side matches being found for a single third client's trade. To avoid deadlock, the server's concurrency protocol for more than two clients results in a slight performance loss in order to ensure participating parties match each other

Test trades are located under 'test_cases'.  
To change test cases or add/remove clients view tests.py.  
