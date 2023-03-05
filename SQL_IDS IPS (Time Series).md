## IDS IPS (Time Series) Dataset 


**SQL Code:**
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

**Output Result:** 
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

