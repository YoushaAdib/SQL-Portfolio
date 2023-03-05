## IDS IPS (Time Series) Dataset 


**SQL: EDA Summary**
```sql  
SELECT
    LABEL,
    COUNT(*)                        AS ATK_COUNT,
    SUM(FLOW_DURATION)              AS TOTAL_FLOW,
    ROUND(SUM(PKT_SIZE_AVG),2)      AS PKT_SIZE,
    COUNT(DISTINCT DST_PORT)        AS PORTS_HIT,
    COUNT(DISTINCT PROTOCOL)        AS PROTOCOL_COUNT,
    LISTAGG(DISTINCT PROTOCOL,', ') WITHIN GROUP (ORDER BY PROTOCOL) AS PROTOCOL, 
    ROUND((MAX(TO_DATE(TIMESTAMP, 'DD/MM/YYYY HH24:MI:SS')) - MIN (TO_DATE(TIMESTAMP, 'DD/MM/YYYY HH24:MI:SS'))) * 24 * 60* 60, 2) AS DURATION_SEC
FROM
    IDS_1
GROUP BY
    LABEL
ORDER BY
    ATK_COUNT DESC, TOTAL_FLOW DESC
```

**Output Table:** 
| LABEL                     | ATK_COUNT | TOTAL_FLOW       | PKT_SIZE      | PORTS_HIT | PROTOCOL_COUNT | PROTOCOL_LIST | DURATION_SEC |
| ------------------------- | --------- | ---------------- | ------------- | --------- | -------------- | -------------- | ------------ |
| Benign                    | 2470181   | 22409850888906   | 279774055.4   | 60790     | 3              | 0, 6, 17      | 1519010973   |
| DDOS attack-HOIC          | 686012    | 6668259505       | 28869597.86   | 1         | 1              | 6             | 1341         |
| DoS attacks-Hulk          | 461912    | 139384537921     | 4212238.79    | 1         | 1              | 6             | 197          |
| Bot                       | 283201    | 21513239072      | 9146596.97    | 1355      | 2              | 0, 6          | 43199        |
| DoS attacks-SlowHTTPTest  | 139890    | 685445           | 0             | 1         | 1              | 6             | 2754         |
| Infilteration             | 53605     | 315846778813     | 3012075.97    | 4569      | 3              | 0, 6, 17      | 119571       |
| DoS attacks-GoldenEye     | 41508     | 466277648662     | 4580854.06    | 1         | 1              | 6             | 2117         |
| DoS attacks-Slowloris     | 10990     | 791063895605     | 743058.72     | 1         | 1              | 6             | 2509         |
| DDOS attack-LOIC-UDP      | 1730      | 200711432887     | 55360.88      | 1         | 1              | 17            | 2065         |
| Brute Force -Web          | 611       | 21654637030      | 159153.74     | 6         | 3              | 0, 6, 17      | 89354        |
| Brute Force -XSS          | 230       | 6592420500       | 90635.74      | 3         | 2              | 6, 17         | 87506        |
| SQL Injection             | 87        | 288468243        | 14745.92      | 1         | 1              | 6             | 118848       |

**SQL: Drilling down to Flow Duration & Attack Packets** 

```sql 
SELECT 
    LABEL,
    SUM(TOT_FWD_PKTS)       AS FWD_PKT,
    SUM(TOT_BWD_PKTS)       AS BWD_PKTS,
    ROUND(SUM(FLOW_BYT),4)           AS FLOW_BYTE,
    ROUND(SUM(FLOW_PKT),4)           AS FLOW_PKT_SUM,
    ROUND(SUM(TOT_FWD_PKTS) - SUM(TOT_BWD_PKTS),4)   AS GAP_PKT_FWD_BWD,
    ROUND(SUM(FLOW_BYT) / SUM (FLOW_PKT),4)          AS RATIO_PKT_BYTE,
    ROUND(SUM(TOT_FWD_PKTS) / COUNT(FLOW_PKT),4)     AS RATIO_COUNT_PKT
FROM 
    IDS_1
GROUP BY 
    LABEL
```

**Output Table:**
| LABEL                   | FWD_PKT   | BWD_PKTS  | FLOW_BYTE      | FLOW_PKT_SUM   | GAP_PKT_FWD_BWD | RATIO_PKT_BYTE | RATIO_COUNT_PKT |
| ------------------------ | --------- | --------- | --------------- | -------------- | ---------------- | -------------- | ---------------- |
| DoS attacks-Hulk          | 1028619   | 111574    | 701977604.6    | 558285098.2    | 917045           | 1.2574         | 2.2269           |
| DDOS attack-LOIC-UDP      | 203017972 | 0         | 59686098.55    | 1865190.58     | 203017972        | 32             | 117351.4289      |
| SQL Injection             | 361       | 220       | 30606.1669     | 2086495.665    | 141              | 0.0147         | 4.1494           |
| Infilteration             | 176910    | 168340    | 6244143788     | 11802264987    | 8570             | 0.5291         | 3.3003           |
| Benign                    | 12567707  | 12481264  | 4.73947E+11    | 59115788560    | 86443            | 8.0173         | 5.0878           |
| DoS attacks-Slowloris     | 84242     | 21076     | 3427886660     | 717558456.6    | 63166            | 4.7772         | 7.6653           |
| Brute Force -XSS          | 22314     | 11307     | 1401224.225    | 1856550.046    | 11007            | 0.7547         | 97.0174          |
| Bot                       | 726712    | 572865    | 5765679152     | 633334238.8    | 153847           | 9.1037         | 2.5661           |
| DDOS attack-HOIC          | 1535774   | 655000    | 42204420412    | 650595089.1    | 880774           | 64.8705        | 2.2387           |
| DoS attacks-GoldenEye     | 154774    | 98976     | 63713655.77    | 362312.4002    | 55798            | 175.8528       | 3.7288           |
| DoS attacks-SlowHTTPTest  | 139890    | 139890    | 0              | 1.02777E+11    | 0                | 0              | 1                |
| Brute Force -Web          | 21556     | 13908     | 2263060.158    | 8513794.006    | 7648             | 0.2658         | 35.2799          |

**SQL: Drilling down to Attack Flgas**

```sql 
-- DRILL DOWN INTO ATTACK FLAGS 
SELECT DISTINCT
    LABEL,
    SUM(SYN_FLAG_CNT) AS SYN,
    SUM(FIN_FLAG_CNT) AS FIN,
    SUM(RST_FLAG_CNT) AS RST,
    SUM(PSH_FLAG_CNT) AS PSH,
    SUM(ACK_FLAG_CNT) AS ACK,
    SUM(URG_FLAG_CNT) AS URG,

    SUM(SYN_FLAG_CNT + FIN_FLAG_CNT + RST_FLAG_CNT + PSH_FLAG_CNT + ACK_FLAG_CNT + URG_FLAG_CNT) AS TOTAL
FROM
    IDS_1
GROUP BY
    LABEL
ORDER BY 
    SYN DESC 
```

**Output Table:** 
| LABEL                   | SYN   | FIN   | RST   | PSH    | ACK    | URG   | TOTAL   |
| ----------------------- | ----- | ----- | ----- | ------ | ------ | ----- | ------- |
| Benign                  | 24323 | 11006 | 597830 | 957639 | 861865 | 112887 | 2565550 |
| DoS attacks-Slowloris   | 3569  | 125   | 0     | 7247   | 3618   | 143   | 14702   |
| Infilteration           | 1365  | 236   | 6571  | 31469  | 6363   | 2236  | 48240   |
| Bot                     | 2     | 0     | 141503| 141503 | 141440 | 2     | 424450  |
| DoS attacks-GoldenEye   | 1     | 1     | 0     | 26860  | 14648  | 0     | 41510   |
| Brute Force -Web        | 1     | 0     | 268   | 269    | 193    | 0     | 731     |
| Brute Force -XSS        | 0     | 0     | 113   | 113    | 112    | 0     | 338     |
| DDOS attack-HOIC        | 0     | 0     | 163750| 163750 | 522262 | 0     | 849762  |
| SQL Injection           | 0     | 0     | 53    | 53     | 34     | 5     | 145     |
| DoS attacks-Hulk        | 0     | 1267  | 0     | 14116  | 446529 | 9855  | 471767  |
| DDOS attack-LOIC-UDP    | 0     | 0     | 0     | 0      | 0      | 0     | 0       |
| DoS attacks-SlowHTTPTest| 0     | 0     | 0     | 139890 | 0      | 0     | 139890  |


