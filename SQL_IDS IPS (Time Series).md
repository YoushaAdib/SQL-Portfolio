## IDS IPS (Time Series) Dataset 


**Analysis:** 
1. Attacker started with different types of Ports enumuration *(60K Ports)* and discovering about the network with various protocols (0, 6, 17).
2. Attacker focused mostly on different types of *DDOS attacks*, in terms of **Count (32%)**, **Packet Size (40+ MB)** and **Durations**. 
3. Majority of the attack vectors focused on specific ports, means either default ports were not changed or attacker could easily grab the port banners. 
 

**SQL: EDA Summary**
```sql  
SELECT
    LABEL,
    COUNT(*)                                AS ATK_COUNT,
    ROUND((COUNT(*) / (SELECT COUNT(*) FROM IDS_1)) * 100, 2) AS ATK_P,
    SUM(FLOW_DURATION)                      AS TOTAL_FLOW,
    ROUND(SUM(PKT_SIZE_AVG)/1000000,2)      AS PKT_SIZE,
    COUNT(DISTINCT DST_PORT)                AS PORTS_HIT,
    COUNT(DISTINCT PROTOCOL)                AS PROTOCOL_COUNT,
    LISTAGG(DISTINCT PROTOCOL,', ') WITHIN GROUP (ORDER BY PROTOCOL) AS PROTOCOL_LIST, 
    ROUND((MAX(TO_DATE(TIMESTAMP, 'DD/MM/YYYY HH24:MI:SS')) - MIN (TO_DATE(TIMESTAMP, 'DD/MM/YYYY HH24:MI:SS'))) * 24 * 60* 60, 2) AS DURATION_SEC
FROM
    IDS_1
GROUP BY
    LABEL
ORDER BY
    ATK_COUNT DESC, TOTAL_FLOW DESC
```

**Output: Table**
| LABEL                   | ATK_COUNT | ATK_P | TOTAL_FLOW      | PKT_SIZE | PORTS_HIT | PROTOCOL_COUNT | PROTOCOL_LIST | DURATION_SEC |
| ----------------------- | --------- | ----- | ---------------- | -------- | --------- | -------------- | ------------- | ------------ |
| Benign                  | 2470181   | 59.52 | 22409850888906   | 279.77   | 60790     | 3              | 0, 6, 17      | 1519010973   |
| DDOS attack-HOIC        | 686012    | 16.53 | 6668259505       | 28.87    | 1         | 1              | 6             | 1341         |
| DoS attacks-Hulk        | 461912    | 11.13 | 139384537921     | 4.21     | 1         | 1              | 6             | 197          |
| Bot                     | 283201    | 6.82  | 21513239072      | 9.15     | 1355      | 2              | 0, 6          | 43199        |
| DoS attacks-SlowHTTPTest| 139890    | 3.37  | 685445           | 0        | 1         | 1              | 6             | 2754         |
| Infilteration           | 53605     | 1.29  | 315846778813     | 3.01     | 4569      | 3              | 0, 6, 17      | 119571       |
| DoS attacks-GoldenEye   | 41508     | 1     | 466277648662     | 4.58     | 1         | 1              | 6             | 2117         |
| DoS attacks-Slowloris   | 10990     | 0.26  | 791063895605     | 0.74     | 1         | 1              | 6             | 2509         |
| DDOS attack-LOIC-UDP    | 1730      | 0.04  | 200711432887     | 0.06     | 1         | 1              | 17            | 2065         |
| Brute Force -Web        | 611       | 0.01  | 21654637030      | 0.16     | 6         | 3              | 0, 6, 17      | 89354        |
| Brute Force -XSS        | 230       | 0.01  | 6592420500       | 0.09     | 3         | 2              | 6, 17        | 87506        |
| SQL Injection           | 87        | 0     | 288468243        | 0.01     | 1         | 1              | 6             | 118848       |
