# IDS IPS (Time Series) Dataset 
First I will be making summary of the dataset in various aspects, to understand the structure as well as the attacker's mindset, and organizational defence. 

## Attack Data Summarization: 
I want to know about the attack counts, attack durations, targated ports, protocols and packet sizes. First query will be orcastrated to find out about it. 

**Analysis: Outcome** 
1. Attacker started with different types of Ports enumuration *(60K Ports)* and discovering about the network with various protocols (0, 6, 17).
2. Attacker focused mostly on different types of *DDOS attacks*, in terms of **Count (32%)**, **Packet Size (40+ MB)** and **Durations**. 
3. Majority of the attack vectors focused on specific ports, means either default ports were not changed or attacker could easily grab the port banners. 
 
 
**SQL Code**
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



## Stat analysis on Packet Data

**Analysis** 


**SQL Code**
```sql
SELECT 
    LABEL,
        CONCAT(
            CASE 
                WHEN CORR (TOT_FWD_PKTS, TOT_BWD_PKTS) > 0 THEN 'POS:'
                WHEN CORR (TOT_FWD_PKTS, TOT_BWD_PKTS) < 0 THEN 'NEG:'
                ELSE 'N/A'
            END, 
            CAST(ROUND(CORR (TOT_FWD_PKTS, TOT_BWD_PKTS),4) AS VARCHAR2(10))
        ) AS CMT_FB,
        CONCAT(    
            CASE 
                WHEN CORR (TOTLEN_FWD_PKTS, TOTLEN_BWD_PKTS) > 0 THEN 'POS:'
                WHEN CORR (TOTLEN_FWD_PKTS, TOTLEN_BWD_PKTS) < 0 THEN 'NEG:'
                ELSE 'N/A'
            END,
            CAST(ROUND(CORR (TOTLEN_FWD_PKTS, TOTLEN_BWD_PKTS),4) AS VARCHAR2(10))
        ) AS CMT_FB_LEN, 
        CONCAT(CONCAT(MAX(FWD_PKT_LEN_MAX), ':'), MIN(FWD_PKT_LEN_MIN)) AS F_LEN,
        REGR_SLOPE(FWD_PKT_LEN_MEAN, BWD_PKT_LEN_MEAN) AS REG_FB_MEAN      
FROM 
    IDS_1
GROUP BY 
    LABEL  
HAVING 
    CORR (TOT_FWD_PKTS, TOT_BWD_PKTS) IS NOT NULL
    AND CORR (TOTLEN_FWD_PKTS, TOTLEN_BWD_PKTS) IS NOT NULL
```

**Output: Table**
|LABEL|CMT_FB|CMT_FB_LEN|F_LEN|REG_FB_MEAN|
|-----|------|----------|-----|-----------|
|Bot|POS:.2256|POS:.8747|1460:0|1.3917|
|Benign|POS:.8039|POS:.0044|64440:0|0.2199|
|DoS attacks-Hulk|POS:.6899|POS:.9524|422:0|0.4727|
|Infilteration|POS:.8294|POS:.0142|1880:0|0.1679|
|DDOS attack-HOIC|POS:1|POS:.9932|365:0|0.4265|
|Brute Force -Web|POS:.9993|POS:.998|1168:0|0.2372|
|Brute Force -XSS|POS:.9998|POS:.9998|680:0|0.1410|
|SQL Injection|POS:.8917|POS:.9647|733:0|0.1506|
|DoS attacks-GoldenEye|POS:.6553|POS:.4112|811:0|0.3027|
|DoS attacks-Slowloris|POS:.7379|NEG:-.087|238:0|0.3025|





