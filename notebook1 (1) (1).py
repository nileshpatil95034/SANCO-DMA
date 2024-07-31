# Databricks notebook source
# Databricks notebook source
# Required imports
from pyspark.sql import SparkSession
from pyspark.sql.functions import col,expr, explode, current_date,regexp_replace,date_format, sum as _sum, count as _count, month, year, avg as _avg, sha2
from pyspark.sql.types import IntegerType, StringType, DoubleType, DateType, ArrayType, StructType, StructField
import pandas as pd
import os 

# COMMAND ----------

spark = SparkSession.builder\
        .appName('InsuranceCraft')\
        .config('Spark.sql.adaptive.enabled',True)\
        .config("Spark.dynamicAllocation.enables",True)\
        .getOrCreate() 

# COMMAND ----------

def encrypt_sensitive_fields(df, input_list_pii_field):
    for field in input_list_pii_field:
        encrypted_field_name = f"{field}_encrypted"
        df = df.withColumn(encrypted_field_name, sha2(col(field), 256).cast(StringType()))
    
    # Drop the original PII fields
    df = df.drop(*input_list_pii_field)
    
    return df 

# COMMAND ----------

# # Vulnerability Issue Fixed
access_key = dbutils.secrets.get("gen2scope", "storagekey")
containerName = dbutils.secrets.get("gen2scope", "containerName")
storageAcName = dbutils.secrets.get("gen2scope", "storageAcName")

mount_point = "/mnt/adls"
account_name = storageAcName
container_name = containerName
access_key = access_key

if not any(mount.mountPoint == mount_point for mount in dbutils.fs.mounts()):
    dbutils.fs.mount(
      source=f"wasbs://{container_name}@{account_name}.blob.core.windows.net",
      mount_point=mount_point,
      extra_configs={f"fs.azure.account.key.{account_name}.blob.core.windows.net": access_key}
    )

display(dbutils.fs.ls(mount_point)) 

# COMMAND ----------

# Define the schema for the JSON data
schema = StructType([
    StructField("_id", StructType([
        StructField("$oid", StringType(), True)
    ]), True),
    StructField("customer_code", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("age", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("age_group", StringType(), True),
    StructField("city", StringType(), True),
    StructField("acquisition_channel", StringType(), True),
    StructField("policy_id", StringType(), True),
    StructField("base_coverage_amt", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("base_premium_amt", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("sale", StructType([
        StructField("sale_id", StructType([
            StructField("$numberInt", StringType(), True)
        ]), True),
        StructField("sale_date", StringType(), True),
        StructField("final_premium_amt", StructType([
            StructField("$numberInt", StringType(), True)
        ]), True),
        StructField("sales_mode", StringType(), True)
    ]), True),
    StructField("revenue", StructType([
        StructField("revenue_id", StructType([
            StructField("$numberInt", StringType(), True)
        ]), True),
        StructField("revenue_date", StringType(), True),
        StructField("revenue_amt", StructType([
            StructField("$numberInt", StringType(), True)
        ]), True)
    ]), True),
    StructField("claims", ArrayType(StructType([
        StructField("$numberInt", StringType(), True)
    ])), True),
    StructField("date", StringType(), True),
    StructField("day", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("month", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("year", StructType([
        StructField("$numberInt", StringType(), True)
    ]), True),
    StructField("day_type", StringType(), True),
    StructField("pii_fields", StructType([
        StructField("pan_number", StringType(), True),
        StructField("aadhaar_number", StringType(), True)
    ]), True),
    StructField("injection_date", StringType(), True)
])

# Define the JSON file path
json_file_path = f'{mount_point}/inbound/shield.json'

# Read the JSON file using the defined schema
df = spark.read.format("json").schema(schema).load(json_file_path)
df.cache()
df.display() 

# COMMAND ----------

################# Schema Transformations like Flatten the nested structure and define data types #######
flattened_df = df.withColumn("sale_id", col("sale.sale_id.$numberInt").cast("int")) \
                 .withColumn("sale_date", col("sale.sale_date").cast("string")) \
                 .withColumn("final_premium_amt", col("sale.final_premium_amt.$numberInt").cast("int")) \
                 .withColumn("sales_mode", col("sale.sales_mode").cast("string")) \
                 .withColumn("revenue_id", col("revenue.revenue_id.$numberInt").cast("int")) \
                 .withColumn("revenue_date", col("revenue.revenue_date").cast("string")) \
                 .withColumn("revenue_amt", col("revenue.revenue_amt.$numberInt").cast("int")) \
                 .withColumn("customer_code", col("customer_code.$numberInt").cast("int")) \
                 .withColumn("age", col("age.$numberInt").cast("int")) \
                 .withColumn("age_group", col("age_group").cast("string")) \
                 .withColumn("city", col("city").cast("string")) \
                 .withColumn("acquisition_channel", col("acquisition_channel").cast("string")) \
                 .withColumn("policy_id", col("policy_id").cast("string")) \
                 .withColumn("base_coverage_amt", col("base_coverage_amt.$numberInt").cast("int")) \
                 .withColumn("base_premium_amt", col("base_premium_amt.$numberInt").cast("int")) \
                 .withColumn("date", col("date").cast("string")) \
                 .withColumn("day", col("day.$numberInt").cast("int")) \
                 .withColumn("month", col("month.$numberInt").cast("int")) \
                 .withColumn("year", col("year.$numberInt").cast("int")) \
                 .withColumn("day_type", col("day_type").cast("string")) \
                 .withColumn("claims", expr("transform(claims, x -> x['$numberInt'])").cast("array<int>")) \
                 .withColumn("pan_number", col("pii_fields.pan_number").cast("string")) \
                 .withColumn("aadhaar_number", col("pii_fields.aadhaar_number").cast("string")) \
                 .withColumn("injection_date", col("injection_date").cast("string")) \
                 .drop("sale", "revenue", "pii_fields","_id")

# Show the transformed DataFrame
flattened_df.display(truncate=False)

# Explode the claims array to calculate KPIs
exploded_df = flattened_df.withColumn("claim_amount", explode("claims")).drop("claims")

### encrypt PII fields by UDF
input_list_pii_field = ["pan_number", "aadhaar_number"]
# Apply the function
exploded_df = encrypt_sensitive_fields(exploded_df, input_list_pii_field)
exploded_df.display(truncate=False)

### Write the Data into bronze layer
bronze_path = f'{mount_point}/outbound/bronze'
exploded_df.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(bronze_path) 

# COMMAND ----------

# Filter the Columns --> By Select Statement [ list of columnss]
columns = ["sale_id", "sale_date", "final_premium_amt", "sales_mode", "revenue_id", "revenue_date", 
           "revenue_amt", "customer_code", "age", "age_group", "city", "acquisition_channel", 
           "policy_id", "base_coverage_amt", "base_premium_amt", "date", "day", "month", 
           "year", "day_type", "claim_amount", "pan_number_encrypted", "aadhaar_number_encrypted"]

silverdf = exploded_df.select(*columns)
# Add New Columns --> By withColumn [as per requirement]
silverdf = silverdf.withColumn("etl_date", date_format(current_date(), "dd-MM-yyyy"))

# Handling nulls --> by fillna() & df.dropna()
silverdf = silverdf.fillna(0).fillna('')

# Handling Duplicate --> by dropDuplicates()
silverdf= silverdf.dropDuplicates()

# Removing Special Character &  --> by regex
silverdf = silverdf.withColumn("age", regexp_replace (col("age"), "[^a-zA-Z0-9 ]", " "))

### Write the Data into silver layer
silver_path = f'{mount_point}/outbound/silver'
silverdf.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(silver_path)
silverdf.display() 

# COMMAND ----------

#gold layer transformation
# Calculate KPIs: Total claims per policy, total claim amount, and average claim amount
total_claims_per_policy = silverdf.groupBy("policy_id").count().withColumnRenamed("count", "total_claims")
total_claims_per_policy.display(truncate=False)

total_claim_amount_per_policy = silverdf.groupBy("policy_id").agg(_sum("claim_amount").alias("total_claim_amount"))
total_claim_amount_per_policy.show(truncate=False)

avg_claim_amount_per_policy = silverdf.groupBy("policy_id").agg(_avg("claim_amount").alias("avg_claim_amount"))
avg_claim_amount_per_policy.show(truncate=False)

# Join KPIs with original DataFrame
transformed_df = silverdf.join(total_claims_per_policy, on="policy_id", how="left") \
                   .join(total_claim_amount_per_policy, on="policy_id", how="left") \
                   .join(avg_claim_amount_per_policy, on="policy_id", how="left")

transformed_df.show()

# Total Customers
total_customers = silverdf.select("customer_code").distinct().count()
print(f"Total Customers: The insurance company has a customer base of {total_customers}")

# Customer Distribution by Age Group
age_group_distribution = silverdf.groupBy("age_group").agg(_count("customer_code").alias("customer_count"))
age_group_distribution.show()

# Customer Acquisition Channels
acquisition_channel_distribution = silverdf.groupBy("acquisition_channel").agg(_count("customer_code").alias("customer_count"))
# acquisition_channel_distribution = silverdf.groupBy("acquisition_channel").count()
acquisition_channel_distribution.show()

# Customer Distribution by City
city_distribution = silverdf.groupBy("city").agg(_count("customer_code").alias("customer_count"))

# Customer Retention Rate (assuming previous data)
# Calculate retention rate for March
monthly_revenue_customers = silverdf.groupBy(year("sale_date").alias("year"), month("sale_date").alias("month")) \
                              .agg(_sum("revenue_amt").alias("total_revenue"), _count("customer_code").alias("total_customers"))

# previous_month_data = monthly_revenue_customers.filter((col("year") == 2023) & (col("month") == 2)).first()
# previous_month_customers = previous_month_data["total_customers"]

# Revenue Generated in Last year of Business month
march_data = monthly_revenue_customers.filter((col("year") == 2023) & (col("month") == 3))
march_data.display() 

# COMMAND ----------

# Write the Data into Gold layer - PART 1
gold_path_claim_policy = f'{mount_point}/outbound/gold/claim_policy'
transformed_df.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(gold_path_claim_policy)
# Write the Data into Gold layer - PART 2
gold_path_age_group = f'{mount_point}/outbound/gold/age_group'
age_group_distribution.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(gold_path_age_group)
# Write the Data into Gold layer - PART 3
gold_path_acquisition_channel = f'{mount_point}/outbound/gold/acquisition_channel'
acquisition_channel_distribution.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(gold_path_acquisition_channel)
# Write the Data into Gold layer - PART 4
gold_path_march_data = f'{mount_point}/outbound/gold/march_data'
march_data.coalesce(1).write.format('csv').option('header', 'true').mode("overwrite").save(gold_path_march_data) 

# COMMAND ----------

# Define the connection details
host =  "sancodbserver.database.windows.net"
port = "1433"
database = "insurancedbs"
username = "nilesh"
password = "Sanco@95"

# Define MSSQL connection properties
mssql_properties = {
    "url": f"jdbc:sqlserver://{host}:{port};databaseName={database};encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;",
    "user": username,
    "password": password,
    "driver": "com.microsoft.sqlserver.jdbc.SQLServerDriver"
}

# Write the DataFrame to MSSQL
silverdf.write.format("jdbc").mode("overwrite").option("dbtable", "InsuranceTransactions").options(**mssql_properties).save()
transformed_df.write.format("jdbc").mode("overwrite").option("dbtable", "transformed_df").options(**mssql_properties).save()
age_group_distribution.write.format("jdbc").mode("overwrite").option("dbtable", "age_group_distribution").options(**mssql_properties).save()
acquisition_channel_distribution.write.format("jdbc").mode("overwrite").option("dbtable", "acquisition_channel_distribution").options(**mssql_properties).save()
march_data.write.format("jdbc").mode("overwrite").option("dbtable", "march_data").options(**mssql_properties).save() 

# COMMAND ----------


