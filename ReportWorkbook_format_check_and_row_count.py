import os
import sys
import logging
import json
import re
import pandas as pd
import pyodbc
import xlsxwriter
from openpyxl import load_workbook
from openpyxl.styles import PatternFill
from openpyxl.utils import get_column_letter
from datetime import datetime
import argparse
import shutil

# Configuration variable to control database verification
PERFORM_DATABASE_VERIFICATION = True  # Set to False to skip database verification

class ProviderDataValidator:
    """Class to validate, format, and verify provider data in Excel reports containing PGIDs and TINs."""

    def __init__(self, config_path='config.json'):
        """Initialize the validator with configuration."""
        self.logger = self._setup_logging()
        self.config = self.load_config(config_path)
        self.db_conn = None

    def _setup_logging(self):
        """Set up logging configuration."""
        # Create logs directory if it doesn't exist
        logs_dir = "logs"
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        # Set log file path
        log_file = os.path.join(logs_dir, "provider_data_validation.log")

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)

    def load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            raise

    def create_db_connection(self):
        """Create a connection to the SQL Server database."""
        try:
            server = self.config.get("db_server", "test")
            database = self.config.get("db_name", "test")

            # Connection string for SQL Server with Windows authentication
            conn_str = f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};Trusted_Connection=yes;'
            conn = pyodbc.connect(conn_str)
            self.logger.info(f"Successfully connected to database {database} on server {server}")
            self.db_conn = conn
            return conn
        except Exception as e:
            self.logger.error(f"Error connecting to database: {e}")
            raise

    def close_db_connection(self):
        """Close the database connection if open."""
        if self.db_conn:
            self.db_conn.close()
            self.logger.info("Database connection closed")
            self.db_conn = None

    def is_valid_pgid(self, pgid):
        """Check if a PGID is valid (2 alpha chars followed by 6 digits)."""
        if pd.isna(pgid):
            return False

        # Convert to string and clean
        pgid_str = str(pgid).strip().lstrip("'")

        # Check format using regex
        pattern = r'^[A-Za-z]{2}\d{6}$'
        return bool(re.match(pattern, pgid_str))

    def is_valid_tin(self, tin):
        """Check if a TIN is valid (9 digits)."""
        if pd.isna(tin):
            return False

        # Convert to string and clean
        tin_str = str(tin).strip().lstrip("'")

        # Check format using regex
        pattern = r'^\d{9}$'
        return bool(re.match(pattern, tin_str))

    def fix_separators(self, value):
        """Fix separators in a value by replacing with commas."""
        if pd.isna(value):
            return value, False, []

        # Convert to string
        value_str = str(value)

        # Define common separators to replace
        separators = [';', '|', '/', '\\', '-', '_', ' and ', ' or ', '\t', '\n']

        # Track which separators were found
        found_separators = []

        # Check if any separators exist
        has_separators = False
        for sep in separators:
            if sep in value_str:
                has_separators = True
                found_separators.append(sep)

        if not has_separators:
            return value_str, False, []

        # Replace separators with commas
        fixed_str = value_str
        for sep in separators:
            fixed_str = fixed_str.replace(sep, ',')

        # Clean up multiple commas and spaces
        fixed_str = re.sub(r',+', ',', fixed_str)
        fixed_str = re.sub(r'\s*,\s*', ',', fixed_str)
        fixed_str = fixed_str.strip(',')

        return fixed_str, True, found_separators

    def validate_cell_format(self, cell_value, validator_func, field_name):
        """Validate a cell that may contain comma-separated values."""
        if pd.isna(cell_value):
            return True, "", 0, []

        # Convert to string and strip whitespace
        cell_str = str(cell_value).strip()

        if not cell_str:
            return True, "", 0, []

        # Split by comma and validate each value
        values = [v.strip() for v in cell_str.split(',')]
        valid_values = []
        invalid_values = []

        for value in values:
            # Remove leading apostrophe if present
            clean_value = value.lstrip("'")
            if validator_func(clean_value):
                valid_values.append(clean_value)
            else:
                invalid_values.append(clean_value)

        is_valid = len(invalid_values) == 0
        error_message = ""

        if not is_valid:
            error_message = f"Invalid {field_name}(s): {', '.join(invalid_values)}"

        return is_valid, error_message, len(valid_values), invalid_values

    def parse_cell_value(self, value, is_tin=False):
        """
        Parse a cell value into a list of items, handling different data types.
        For TINs, ensure they are properly formatted as strings with leading zeros preserved.
        """
        if pd.isna(value):
            return []

        # Convert to string first
        value_str = str(value).strip()
        if not value_str:
            return []

        # Split by comma and clean up
        items = [item.strip() for item in value_str.split(',') if item.strip()]

        # For TINs, ensure proper formatting
        if is_tin:
            # Remove any leading apostrophes and ensure 9 digits with leading zeros
            items = [item.lstrip("'").zfill(9) for item in items]

        return items

    def build_sql_query(self, pgids, tins):
        """Build SQL query based on PGIDs and TINs."""
        # Build filter conditions with proper string formatting for TINs
        pgid_filter = f"PGID IN ({', '.join(['?' for _ in pgids])})" if pgids else ""

        # For TINs, we need to ensure they're treated as strings
        if tins:
            tin_filter = f"PROVIDERTIN IN ({', '.join(['?' for _ in tins])})"
        else:
            tin_filter = ""

        # Combine filters
        where_clause = ""
        filters = []
        if pgid_filter:
            filters.append(pgid_filter)
        if tin_filter:
            filters.append(tin_filter)

        if filters:
            where_clause = " WHERE " + " AND ".join(filters)

        # Build the complete SQL query
        sql_query = f"SELECT COUNT(*) AS RecordCount FROM RX_PROVIDER_COLLAB.dbo.STAR_PROVIDER_DATA{where_clause}"

        # Prepare parameters list
        params = []
        params.extend(pgids)
        params.extend(tins)

        return sql_query, params

    def verify_and_clean_report(self, report_path):
        """
        Verify and clean the format of PGIDs and TINs in the report workbook.
        Creates a single output file with cleaned data and highlights for issues.
        """
        try:
            # Load the data with pandas
            df = pd.read_excel(report_path, sheet_name='Report')

            if df.empty:
                self.logger.error("Report sheet is empty")
                raise ValueError("Report sheet is empty")

            # Create a copy of the original data for comparison
            original_df = df.copy()

            # Create validation results dataframe
            validation_results = []

            # Statistics
            valid_rows = 0
            invalid_rows = 0
            empty_rows = 0
            rows_with_invalid_pgids = 0
            rows_with_invalid_tins = 0
            rows_with_separators_fixed = 0
            rows_with_tin_formatted = 0

            # Track which rows have issues that couldn't be fixed
            rows_with_unfixable_issues = []

            # Process each row
            for i in range(len(df)):
                pgid_value = df.iloc[i, 0]  # First column (PGID)
                tin_value = df.iloc[i, 1]   # Second column (TIN)

                row_result = {
                    'Row': i + 2,  # Excel rows start at 1, with header at row 1
                    'PGID Valid': "N/A",
                    'PGID Error': "",
                    'Valid PGID Count': 0,
                    'TIN Valid': "N/A",
                    'TIN Error': "",
                    'Valid TIN Count': 0,
                    'Separators Fixed': "No",
                    'TIN Formatted as Text': "No",
                    'Overall Status': ""
                }

                # Skip completely empty rows
                if pd.isna(pgid_value) and pd.isna(tin_value):
                    empty_rows += 1
                    row_result['Overall Status'] = "Empty Row"
                    validation_results.append(row_result)
                    continue

                # Fix separators in PGID cell
                pgid_fixed = False
                if not pd.isna(pgid_value):
                    fixed_pgid, was_fixed, _ = self.fix_separators(pgid_value)
                    if was_fixed:
                        df.iloc[i, 0] = fixed_pgid
                        pgid_fixed = True
                        pgid_value = fixed_pgid  # Update for validation

                # Fix separators in TIN cell
                tin_fixed = False
                if not pd.isna(tin_value):
                    fixed_tin, was_fixed, _ = self.fix_separators(tin_value)
                    if was_fixed:
                        df.iloc[i, 1] = fixed_tin
                        tin_fixed = True
                        tin_value = fixed_tin  # Update for validation

                # Track if separators were fixed
                separators_fixed = pgid_fixed or tin_fixed
                if separators_fixed:
                    rows_with_separators_fixed += 1
                    row_result['Separators Fixed'] = "Yes"

                # Format TIN as text (will be applied when writing to Excel)
                if not pd.isna(tin_value):
                    rows_with_tin_formatted += 1
                    row_result['TIN Formatted as Text'] = "Yes"

                # Validate PGID format
                pgid_valid, pgid_error, valid_pgid_count, invalid_pgids = self.validate_cell_format(
                    pgid_value, self.is_valid_pgid, "PGID"
                )

                # Validate TIN format
                tin_valid, tin_error, valid_tin_count, invalid_tins = self.validate_cell_format(
                    tin_value, self.is_valid_tin, "TIN"
                )

                # Update validation results
                row_result['PGID Valid'] = "Yes" if pgid_valid else "No"
                row_result['PGID Error'] = pgid_error
                row_result['Valid PGID Count'] = valid_pgid_count
                row_result['TIN Valid'] = "Yes" if tin_valid else "No"
                row_result['TIN Error'] = tin_error
                row_result['Valid TIN Count'] = valid_tin_count

                # Determine overall status
                if pgid_valid and tin_valid:
                    row_result['Overall Status'] = "Valid"
                    valid_rows += 1
                else:
                    row_result['Overall Status'] = "Invalid"
                    invalid_rows += 1
                    rows_with_unfixable_issues.append(i)

                    if not pgid_valid:
                        rows_with_invalid_pgids += 1

                    if not tin_valid:
                        rows_with_invalid_tins += 1

                validation_results.append(row_result)

            # Create summary data
            summary_data = {
                'Category': [
                    'Total Rows', 'Valid Rows', 'Invalid Rows', 'Empty Rows',
                    'Rows with Invalid PGIDs', 'Rows with Invalid TINs',
                    'Rows with Separators Fixed', 'Rows with TIN Formatted as Text'
                ],
                'Count': [
                    len(df), valid_rows, invalid_rows, empty_rows,
                    rows_with_invalid_pgids, rows_with_invalid_tins,
                    rows_with_separators_fixed, rows_with_tin_formatted
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            validation_df = pd.DataFrame(validation_results)

            # Create output filename
            directory, filename = os.path.split(report_path)
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"{name}_validated_{timestamp}{ext}"
            output_path = os.path.join(directory, output_filename)

            # Write the combined output file with proper formatting and highlighting
            self._write_combined_report(df, validation_df, summary_df, output_path, rows_with_unfixable_issues)

            self.logger.info(f"Format validation and cleaning completed. Results saved to {output_path}")

            # Return validation statistics and output path
            return {
                "total_rows": len(df),
                "valid_rows": valid_rows,
                "invalid_rows": invalid_rows,
                "empty_rows": empty_rows,
                "rows_with_invalid_pgids": rows_with_invalid_pgids,
                "rows_with_invalid_tins": rows_with_invalid_tins,
                "rows_with_separators_fixed": rows_with_separators_fixed,
                "rows_with_tin_formatted": rows_with_tin_formatted,
                "output_path": output_path
            }

        except Exception as e:
            self.logger.error(f"Error verifying report format: {e}")
            raise

    def _write_combined_report(self, df, validation_df, summary_df, output_path, rows_with_issues):
        """Write a combined report with cleaned data and validation results using XlsxWriter."""
        # Replace NaN and inf values with empty string for all DataFrames
        df = df.replace([pd.NA, pd.NaT, float('inf'), float('-inf')], '').fillna('')
        validation_df = validation_df.replace([pd.NA, pd.NaT, float('inf'), float('-inf')], '').fillna('')
        summary_df = summary_df.replace([pd.NA, pd.NaT, float('inf'), float('-inf')], '').fillna('')

        # Create a Pandas Excel writer using XlsxWriter as the engine
        writer = pd.ExcelWriter(output_path, engine='xlsxwriter')

        # Write the dataframes to the Excel file
        df.to_excel(writer, sheet_name='Report', index=False)
        validation_df.to_excel(writer, sheet_name='Validation Results', index=False)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)

        # Get workbook and worksheet objects
        workbook = writer.book
        report_sheet = writer.sheets['Report']
        validation_sheet = writer.sheets['Validation Results']
        summary_sheet = writer.sheets['Summary']

        # Define formats
        text_format = workbook.add_format({'num_format': '@'})
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#D7E4BC',
            'border': 1
        })
        error_format = workbook.add_format({
            'bg_color': '#FFC7CE',  # Light red
            'font_color': '#9C0006'
        })

        # Format the TIN column as text to preserve leading zeros
        report_sheet.set_column('B:B', 15, text_format)

        # Format headers
        for col_num, value in enumerate(df.columns.values):
            report_sheet.write(0, col_num, value, header_format)

        # Highlight rows with issues that couldn't be fixed
        for row_idx in rows_with_issues:
            excel_row = row_idx + 1  # +1 because we have a header row
            for col_idx in range(df.shape[1]):
                report_sheet.write(excel_row, col_idx, df.iloc[row_idx, col_idx], error_format)

        # Format validation sheet
        validation_sheet.set_column('A:J', 15)
        for col_num, value in enumerate(validation_df.columns.values):
            validation_sheet.write(0, col_num, value, header_format)

        # Add conditional formatting to highlight invalid rows in the validation sheet
        validation_sheet.conditional_format(1, 0, len(validation_df), len(validation_df.columns) - 1, {
            'type': 'formula',
            'criteria': '=$J2="Invalid"',
            'format': error_format
        })

        # Format summary sheet
        summary_sheet.set_column('A:B', 30)
        for col_num, value in enumerate(summary_df.columns.values):
            summary_sheet.write(0, col_num, value, header_format)

        # Add a chart to the summary sheet
        chart = workbook.add_chart({'type': 'column'})

        # Configure the chart
        chart.add_series({
            'name': 'Validation Results',
            'categories': ['Summary', 1, 0, 8, 0],
            'values': ['Summary', 1, 1, 8, 1],
            'data_labels': {'value': True}
        })

        chart.set_title({'name': 'Validation Results Summary'})
        chart.set_x_axis({'name': 'Category'})
        chart.set_y_axis({'name': 'Count'})
        chart.set_style(11)

        # Insert the chart into the summary sheet
        summary_sheet.insert_chart('D2', chart, {'x_scale': 1.5, 'y_scale': 1.5})

        # Close the Pandas Excel writer and output the Excel file
        writer.close()

        # Now open the file with openpyxl to "fix" the text-formatted numbers
        self._fix_text_formatted_numbers(output_path)

        self.logger.info(f"Combined report with validation results saved to {output_path}")

    def _fix_text_formatted_numbers(self, file_path):
        """
        Open the Excel file and force Excel to recognize numbers stored as text
        by adding a leading apostrophe if not already present.
        """
        try:
            # Create a backup of the file first
            backup_path = file_path + ".bak"
            shutil.copy2(file_path, backup_path)

            # Load the workbook
            wb = load_workbook(file_path)
            sheet = wb['Report']

            # Get the TIN column (column B or index 1)
            tin_col_idx = 1

            # Skip the header row
            for row in range(2, sheet.max_row + 1):
                cell = sheet.cell(row=row, column=tin_col_idx + 1)  # +1 because openpyxl is 1-indexed

                # Only process cells that have values
                if cell.value:
                    # Convert to string if not already
                    if not isinstance(cell.value, str):
                        cell.value = str(cell.value)

                    # Add leading apostrophe only if not already present
                    if not cell.value.startswith("'"):
                        cell.value = f"'{cell.value}"

            # Save the workbook
            wb.save(file_path)

            # Remove the backup if everything went well
            os.remove(backup_path)

            self.logger.info("Successfully fixed text-formatted numbers in the TIN column")
        except Exception as e:
            self.logger.error(f"Error fixing text-formatted numbers: {e}")
            # If there was an error, restore from backup
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, file_path)
                os.remove(backup_path)
                self.logger.info("Restored file from backup due to error")

    def verify_database_records(self, report_path):
        """
        Check each row in the report workbook, get record counts from database,
        and add new columns with the counts.
        """
        try:
            # Ensure we have a database connection
            if not self.db_conn:
                self.create_db_connection()

            # Make a backup of the report
            directory, filename = os.path.split(report_path)
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            db_check_filename = f"{name}_db_check_{timestamp}{ext}"
            db_check_path = os.path.join(directory, db_check_filename)
            shutil.copy2(report_path, db_check_path)

            # Load the workbook
            wb = load_workbook(db_check_path)

            # Check if 'Report' sheet exists
            if 'Report' not in wb.sheetnames:
                self.logger.error("Report sheet not found in workbook")
                raise ValueError("Report sheet not found in workbook")

            report_sheet = wb['Report']

            # Find the last row and column
            last_row = report_sheet.max_row
            last_col = report_sheet.max_column

            # Add headers for the new columns
            new_col = last_col + 1
            report_sheet.cell(row=1, column=new_col).value = "DB Record Count"
            report_sheet.cell(row=1, column=new_col+1).value = "PGID Only Count"
            report_sheet.cell(row=1, column=new_col+2).value = "TIN Only Count"

            # Statistics for summary
            zero_count = 0
            with_records_count = 0
            error_count = 0
            total_records = 0
            pgid_only_worked = 0
            tin_only_worked = 0

            # Process each row
            for row in range(2, last_row + 1):
                # Get PGIDs and TINs from the row
                pgids_cell = report_sheet.cell(row=row, column=1).value
                tins_cell = report_sheet.cell(row=row, column=2).value

                # Skip empty rows
                if not pgids_cell and not tins_cell:
                    report_sheet.cell(row=row, column=new_col).value = "N/A"
                    report_sheet.cell(row=row, column=new_col+1).value = "N/A"
                    report_sheet.cell(row=row, column=new_col+2).value = "N/A"
                    continue

                # Parse the values into lists using the safe parsing function
                pgids = self.parse_cell_value(pgids_cell)
                # Special handling for TINs to preserve leading zeros
                tins = self.parse_cell_value(tins_cell, is_tin=True)

                # If all lists are empty, mark as N/A
                if not pgids and not tins:
                    report_sheet.cell(row=row, column=new_col).value = "N/A"
                    report_sheet.cell(row=row, column=new_col+1).value = "N/A"
                    report_sheet.cell(row=row, column=new_col+2).value = "N/A"
                    continue

                # Build the SQL query
                sql_query, params = self.build_sql_query(pgids, tins)

                # Log the query for debugging
                param_str = ', '.join([f"'{p}'" for p in params])
                self.logger.info(f"Row {row} Query: {sql_query} with params [{param_str}]")

                try:
                    # Execute the query
                    cursor = self.db_conn.cursor()
                    cursor.execute(sql_query, params)
                    record_count = cursor.fetchone()[0]
                    cursor.close()

                    # Add the record count to the new column
                    report_sheet.cell(row=row, column=new_col).value = record_count

                    # Log the result
                    self.logger.info(f"Row {row}: Found {record_count} records")

                    # Initialize PGID and TIN only counts
                    pgid_count = "N/A"
                    tin_count = "N/A"

                    # If no records found, try individual queries for troubleshooting
                    if record_count == 0 and (pgids or tins):
                        self.logger.info(f"Row {row}: No records found, trying individual queries for troubleshooting")

                        # Try PGID only if applicable
                        if pgids:
                            pgid_query = f"SELECT COUNT(*) FROM RX_PROVIDER_COLLAB.dbo.STAR_PROVIDER_DATA WHERE PGID IN ({', '.join(['?' for _ in pgids])})"
                            cursor = self.db_conn.cursor()
                            cursor.execute(pgid_query, pgids)
                            pgid_count = cursor.fetchone()[0]
                            cursor.close()
                            self.logger.info(f"  PGID only query found {pgid_count} records")

                            if pgid_count > 0:
                                pgid_only_worked += 1

                        # Try TIN only if applicable
                        if tins:
                            tin_query = f"SELECT COUNT(*) FROM RX_PROVIDER_COLLAB.dbo.STAR_PROVIDER_DATA WHERE PROVIDERTIN IN ({', '.join(['?' for _ in tins])})"
                            cursor = self.db_conn.cursor()
                            cursor.execute(tin_query, tins)
                            tin_count = cursor.fetchone()[0]
                            cursor.close()
                            self.logger.info(f"  TIN only query found {tin_count} records")

                            if tin_count > 0:
                                tin_only_worked += 1

                            # If still no records, try a direct query with the TIN value for debugging
                            if tin_count == 0:
                                for tin in tins:
                                    direct_query = f"SELECT TOP 5 PGID, PROVIDERTIN FROM RX_PROVIDER_COLLAB.dbo.STAR_PROVIDER_DATA WHERE PROVIDERTIN LIKE ?"
                                    cursor = self.db_conn.cursor()
                                    cursor.execute(direct_query, [f"%{tin}%"])
                                    direct_results = cursor.fetchall()
                                    cursor.close()
                                    if direct_results:
                                        self.logger.info(f"  Found similar TINs for {tin}: {[f'{row.PGID}:{row.PROVIDERTIN}' for row in direct_results]}")
                                    else:
                                        self.logger.info(f"  No similar TINs found for {tin}")

                    # Add the PGID and TIN only counts to the new columns
                    report_sheet.cell(row=row, column=new_col+1).value = pgid_count
                    report_sheet.cell(row=row, column=new_col+2).value = tin_count

                    # Update statistics for summary
                    if record_count == 0:
                        zero_count += 1
                    else:
                        with_records_count += 1
                        total_records += record_count

                except Exception as e:
                    self.logger.error(f"Error executing query for row {row}: {e}")
                    report_sheet.cell(row=row, column=new_col).value = "ERROR"
                    report_sheet.cell(row=row, column=new_col+1).value = "ERROR"
                    report_sheet.cell(row=row, column=new_col+2).value = "ERROR"
                    error_count += 1

            # Create a new sheet for the summary
            if "DB Summary" in wb.sheetnames:
                wb.remove(wb["DB Summary"])
            summary_sheet = wb.create_sheet("DB Summary")

            # Add headers
            summary_sheet.cell(row=1, column=1).value = "Category"
            summary_sheet.cell(row=1, column=2).value = "Count"

            # Add summary data
            summary_sheet.cell(row=2, column=1).value = "Rows with zero records"
            summary_sheet.cell(row=2, column=2).value = zero_count

            summary_sheet.cell(row=3, column=1).value = "Rows with records"
            summary_sheet.cell(row=3, column=2).value = with_records_count

            summary_sheet.cell(row=4, column=1).value = "Rows with errors"
            summary_sheet.cell(row=4, column=2).value = error_count

            summary_sheet.cell(row=5, column=1).value = "Total records in database"
            summary_sheet.cell(row=5, column=2).value = total_records

            summary_sheet.cell(row=6, column=1).value = "Rows where PGID only worked"
            summary_sheet.cell(row=6, column=2).value = pgid_only_worked

            summary_sheet.cell(row=7, column=1).value = "Rows where TIN only worked"
            summary_sheet.cell(row=7, column=2).value = tin_only_worked

            # Save the workbook
            wb.save(db_check_path)
            self.logger.info(f"Database verification completed. Results saved to {db_check_path}")

            return {
                "zero_count": zero_count,
                "with_records_count": with_records_count,
                "error_count": error_count,
                "total_records": total_records,
                "pgid_only_worked": pgid_only_worked,
                "tin_only_worked": tin_only_worked,
                "output_path": db_check_path
            }

        except Exception as e:
            self.logger.error(f"Error verifying database records: {e}")
            raise

    def process_report(self, report_path=None):
        """
        Complete process to validate, clean, and verify a report against the database.
        """
        try:
            # Get report path from args or config
            if not report_path:
                report_path = self.config["report_workbook_path"]

            self.logger.info(f"Starting processing of report: {report_path}")

            # Step 1: Verify and clean the report format
            self.logger.info("Step 1: Verifying and cleaning report format...")
            format_results = self.verify_and_clean_report(report_path)

            # Check if database verification should be performed
            if not PERFORM_DATABASE_VERIFICATION:
                self.logger.info("Database verification skipped as configured")
                return {
                    "format_results": format_results,
                    "final_output_path": format_results["output_path"]
                }

            # Step 2: Verify the data against the database
            self.logger.info("Step 2: Verifying data against database...")
            db_results = self.verify_database_records(format_results["output_path"])

            # Log the combined results
            self.logger.info("Report processing completed successfully")
            self.logger.info(f"Format validation results:")
            self.logger.info(f"  Total rows: {format_results['total_rows']}")
            self.logger.info(f"  Valid rows: {format_results['valid_rows']}")
            self.logger.info(f"  Invalid rows: {format_results['invalid_rows']}")
            self.logger.info(f"  Empty rows: {format_results['empty_rows']}")
            self.logger.info(f"  Rows with invalid PGIDs: {format_results['rows_with_invalid_pgids']}")
            self.logger.info(f"  Rows with invalid TINs: {format_results['rows_with_invalid_tins']}")
            self.logger.info(f"  Rows with separators fixed: {format_results['rows_with_separators_fixed']}")

            self.logger.info(f"Database verification results:")
            self.logger.info(f"  Rows with zero records: {db_results['zero_count']}")
            self.logger.info(f"  Rows with records: {db_results['with_records_count']}")
            self.logger.info(f"  Total records in database: {db_results['total_records']}")
            self.logger.info(f"  Rows where PGID only worked: {db_results['pgid_only_worked']}")
            self.logger.info(f"  Rows where TIN only worked: {db_results['tin_only_worked']}")

            # Return the combined results
            return {
                "format_results": format_results,
                "db_results": db_results,
                "final_output_path": db_results["output_path"]
            }

        except Exception as e:
            self.logger.error(f"Error processing report: {e}")
            raise
        finally:
            # Always close the database connection
            self.close_db_connection()

    def create_final_report(self, results):
        """
        Create a final consolidated report with all validation and verification results.
        """
        try:
            format_results = results["format_results"]
            db_results = results["db_results"]

            # Create output filename
            directory, filename = os.path.split(db_results["output_path"])
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            final_filename = f"{name}_final_{timestamp}{ext}"
            final_path = os.path.join(directory, final_filename)

            # Copy the DB verification file as our base
            shutil.copy2(db_results["output_path"], final_path)

            # Load the workbook
            wb = load_workbook(final_path)

            # Create a new summary sheet
            if "Final Summary" in wb.sheetnames:
                wb.remove(wb["Final Summary"])
            summary_sheet = wb.create_sheet("Final Summary", 0)  # Make it the first sheet

            # Add headers
            summary_sheet.cell(row=1, column=1).value = "Category"
            summary_sheet.cell(row=1, column=2).value = "Value"

            # Add format validation results
            row = 2
            summary_sheet.cell(row=row, column=1).value = "--- FORMAT VALIDATION RESULTS ---"
            summary_sheet.cell(row=row, column=2).value = ""
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Total Rows"
            summary_sheet.cell(row=row, column=2).value = format_results["total_rows"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Valid Format Rows"
            summary_sheet.cell(row=row, column=2).value = format_results["valid_rows"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Invalid Format Rows"
            summary_sheet.cell(row=row, column=2).value = format_results["invalid_rows"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Empty Rows"
            summary_sheet.cell(row=row, column=2).value = format_results["empty_rows"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Invalid PGIDs"
            summary_sheet.cell(row=row, column=2).value = format_results["rows_with_invalid_pgids"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Invalid TINs"
            summary_sheet.cell(row=row, column=2).value = format_results["rows_with_invalid_tins"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Separators Fixed"
            summary_sheet.cell(row=row, column=2).value = format_results["rows_with_separators_fixed"]
            row += 1

            # Add database verification results
            row += 1
            summary_sheet.cell(row=row, column=1).value = "--- DATABASE VERIFICATION RESULTS ---"
            summary_sheet.cell(row=row, column=2).value = ""
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Zero Records"
            summary_sheet.cell(row=row, column=2).value = db_results["zero_count"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Records"
            summary_sheet.cell(row=row, column=2).value = db_results["with_records_count"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows with Database Errors"
            summary_sheet.cell(row=row, column=2).value = db_results["error_count"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Total Records in Database"
            summary_sheet.cell(row=row, column=2).value = db_results["total_records"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows where PGID Only Worked"
            summary_sheet.cell(row=row, column=2).value = db_results["pgid_only_worked"]
            row += 1

            summary_sheet.cell(row=row, column=1).value = "Rows where TIN Only Worked"
            summary_sheet.cell(row=row, column=2).value = db_results["tin_only_worked"]
            row += 1

            # Add overall assessment
            row += 1
            summary_sheet.cell(row=row, column=1).value = "--- OVERALL ASSESSMENT ---"
            summary_sheet.cell(row=row, column=2).value = ""
            row += 1

            # Calculate percentage of valid rows
            valid_percent = (format_results["valid_rows"] / format_results["total_rows"]) * 100 if format_results[
                                                                                                       "total_rows"] > 0 else 0
            summary_sheet.cell(row=row, column=1).value = "Percentage of Valid Format Rows"
            summary_sheet.cell(row=row, column=2).value = f"{valid_percent:.2f}%"
            row += 1

            # Calculate percentage of rows with database records
            db_match_percent = (db_results["with_records_count"] / (
                    format_results["total_rows"] - format_results["empty_rows"])) * 100 if (format_results[
                                                                                                "total_rows"] -
                                                                                            format_results[
                                                                                                "empty_rows"]) > 0 else 0
            summary_sheet.cell(row=row, column=1).value = "Percentage of Rows with Database Records"
            summary_sheet.cell(row=row, column=2).value = f"{db_match_percent:.2f}%"
            row += 1

            # Overall status
            overall_status = "PASSED"
            issues = []

            if format_results["invalid_rows"] > 0:
                overall_status = "FAILED"
                issues.append(f"{format_results['invalid_rows']} rows with invalid format")

            if db_results["zero_count"] > 0:
                if overall_status != "FAILED":
                    overall_status = "WARNING"
                issues.append(f"{db_results['zero_count']} rows with no database records")

            summary_sheet.cell(row=row, column=1).value = "Overall Status"
            summary_sheet.cell(row=row, column=2).value = overall_status
            row += 1

            if issues:
                summary_sheet.cell(row=row, column=1).value = "Issues"
                summary_sheet.cell(row=row, column=2).value = "; ".join(issues)

            # Format the summary sheet
            for col in range(1, 3):
                summary_sheet.column_dimensions[get_column_letter(col)].width = 40

            # Apply formatting to headers
            header_fill = PatternFill(start_color="D7E4BC", end_color="D7E4BC", fill_type="solid")
            summary_sheet.cell(row=1, column=1).fill = header_fill
            summary_sheet.cell(row=1, column=2).fill = header_fill

            # Apply formatting to section headers
            section_fill = PatternFill(start_color="E6E6E6", end_color="E6E6E6", fill_type="solid")
            for r in [2, 11, 19]:
                summary_sheet.cell(row=r, column=1).fill = section_fill
                summary_sheet.cell(row=r, column=2).fill = section_fill

            # Save the workbook
            wb.save(final_path)
            self.logger.info(f"Final consolidated report saved to {final_path}")

            return final_path

        except Exception as e:
            self.logger.error(f"Error creating final report: {e}")
            raise

def main():
    """Main function to run the provider data validation process."""
    try:
        # Parse command line arguments
        args = parse_args()

        # Initialize the validator
        validator = ProviderDataValidator(config_path=args.config)

        # Process the report
        if args.format_only:
            # Only perform format validation
            format_results = validator.verify_and_clean_report(args.report)
            validator.logger.info("Format validation completed successfully")
            validator.logger.info(f"Results saved to {format_results['output_path']}")
        else:
            # Perform complete processing
            results = validator.process_report(args.report)

            # Create final consolidated report if database verification was performed
            if "db_results" in results:
                final_path = validator.create_final_report(results)
                validator.logger.info(f"Final consolidated report saved to {final_path}")
            else:
                validator.logger.info("Final report not created as database verification was skipped")

    except Exception as e:
        logging.error(f"Error in main: {e}")
        sys.exit(1)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Validate, clean, and verify provider data in Excel reports')
    parser.add_argument('--config', default='config.json', help='Path to config file')
    parser.add_argument('--report', help='Path to report workbook (overrides config)')
    parser.add_argument('--format-only', action='store_true',
                        help='Only perform format validation (skip database verification)')
    return parser.parse_args()

if __name__ == "__main__":
    sys.exit(main())
