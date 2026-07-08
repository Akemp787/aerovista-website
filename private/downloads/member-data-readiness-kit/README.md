# Member Data Readiness Kit Delivery Files

Place the paid product files in this folder before enabling live Stripe checkout.

Preferred single attachment:

- `Member_Data_Readiness_Kit.zip`

Fallback individual attachments:

- `Member_Data_Readiness_Kit_Guide.pdf`
- `Member_Data_Readiness_Kit_Workbook.xlsx`

The Node server blocks direct public access to the `private/` folder. After a verified Stripe payment, the webhook emails the ZIP if present. If the ZIP is not present, it emails the PDF and workbook when both are available.
