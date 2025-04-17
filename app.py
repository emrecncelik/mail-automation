import os
import base64
import json
import streamlit as st
import pandas as pd
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Define the scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.compose"]


def get_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_info(json.load(open("token.json")))

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=8080)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds


def create_draft(from_email, to_email, subject, message_body, attachments):
    creds = get_credentials()

    try:
        service = build("gmail", "v1", credentials=creds)

        # Create multipart message
        message = MIMEMultipart()
        message.attach(MIMEText(message_body, "plain"))
        message["From"] = from_email
        message["To"] = to_email
        message["Subject"] = subject

        # Attach files
        for attachment in attachments:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment["content"])

            # Encode and add header
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {attachment['filename']}",
            )

            # Attach the file
            message.attach(part)

        # Encode message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {"message": {"raw": encoded_message}}

        # Create draft
        draft = (
            service.users().drafts().create(userId="me", body=create_message).execute()
        )

        return True, f'Draft created for {to_email} with ID: {draft["id"]}'

    except HttpError as error:
        return False, f"Error for {to_email}: {error}"


# Streamlit UI
st.title("Automated Email Draft Creator")

# From email
from_email = st.text_input("From Email", placeholder="your@email.com")

# Subject
subject = st.text_input("Subject", placeholder="Email Subject")

# Message body
message_body = st.text_area(
    "Message Body", placeholder="Type your email message here..."
)

# Upload CSV file with names and emails
st.subheader("Step 1: Upload CSV with Recipients")
st.write("Upload a CSV file with columns: name, email")
csv_example = """name,email
John Doe,john.doe@example.com
Jane Smith,jane.smith@example.com"""
st.code(csv_example)

uploaded_csv = st.file_uploader("Upload Recipient CSV", type=["csv"])

# File suffix configuration
st.subheader("Step 2: Configure File Patterns")
st.write("Define the suffixes for matching files (without file extension)")

# Use columns for a cleaner layout
col1, col2 = st.columns(2)
with col1:
    suffix1 = st.text_input("Suffix 1", value="_fatura", placeholder="_fatura")
with col2:
    suffix2 = st.text_input("Suffix 2", value="_sertifika", placeholder="_sertifika")

# Option to add more suffixes
if "suffixes" not in st.session_state:
    st.session_state.suffixes = []


def add_suffix():
    st.session_state.suffixes.append("")


# Display additional suffix fields
for i, suffix_val in enumerate(st.session_state.suffixes):
    suffix_key = f"suffix_{i+3}"
    st.session_state.suffixes[i] = st.text_input(
        f"Suffix {i+3}", value=suffix_val, key=suffix_key
    )

if st.button("Add Another Suffix"):
    add_suffix()

# Gather all suffixes
suffixes = [suffix1, suffix2] + st.session_state.suffixes
suffixes = [s.strip() for s in suffixes if s.strip()]

# Upload PDF files
st.subheader("Step 3: Upload PDF Files")
st.write(
    f"Upload all PDF files following naming pattern: name_with_underscores{suffixes[0] if suffixes else '_fatura'}.pdf, etc."
)
uploaded_files = st.file_uploader(
    "Upload PDFs", type=["pdf"], accept_multiple_files=True
)

# Preview and processing logic
if uploaded_csv is not None and uploaded_files:
    # Read CSV
    recipients_df = pd.read_csv(uploaded_csv)

    # Check required columns
    required_columns = ["name", "email"]
    missing_columns = [
        col for col in required_columns if col not in recipients_df.columns
    ]

    if missing_columns:
        st.error(f"CSV is missing required columns: {', '.join(missing_columns)}")
    else:
        # Display recipients
        st.write(f"Found {len(recipients_df)} recipients:")
        st.dataframe(recipients_df)

        # Process uploaded files
        st.write(f"Found {len(uploaded_files)} PDF files:")
        file_info = []

        for upload_file in uploaded_files:
            # Get filename and match pattern
            filename = upload_file.name
            st.write(f"- {filename}")

            # Save content for processing
            content = upload_file.read()
            file_info.append({"filename": filename, "content": content})

        # Match recipients with files
        matching_results = []

        for _, recipient in recipients_df.iterrows():
            full_name = recipient["name"]
            email = recipient["email"]
            recipient_files = []

            # Replace spaces with underscores for matching
            name_pattern = full_name.lower().replace(" ", "_")

            for file in file_info:
                filename_lower = file["filename"].lower()

                # Check if name pattern exists in the filename
                if name_pattern in filename_lower:
                    # Check if any of the suffixes match
                    suffix_matched = False
                    if (
                        not suffixes
                    ):  # If no suffixes specified, match any file with the name pattern
                        suffix_matched = True
                    else:
                        for suffix in suffixes:
                            suffix_lower = suffix.lower()
                            if f"{name_pattern}{suffix_lower}" in filename_lower:
                                suffix_matched = True
                                break

                    if suffix_matched:
                        recipient_files.append(
                            {"filename": file["filename"], "content": file["content"]}
                        )

            matching_results.append(
                {"name": full_name, "email": email, "files": recipient_files}
            )

        # Display matching results
        st.subheader("File Matching Preview")
        for result in matching_results:
            files_text = ", ".join([f["filename"] for f in result["files"]])
            if files_text:
                st.write(f"✅ {result['name']} ({result['email']}): {files_text}")
            else:
                st.write(
                    f"❌ {result['name']} ({result['email']}): No matching files found"
                )

        # Submit button
        if st.button("Create Drafts"):
            if not from_email:
                st.error("From Email is required")
            elif not subject:
                st.error("Subject is required")
            elif not message_body:
                st.error("Message body is required")
            else:
                results = []
                progress_bar = st.progress(0)

                # Process each recipient
                for i, result in enumerate(matching_results):
                    if result["files"]:  # Only create drafts if files were found
                        with st.spinner(f"Creating draft for {result['email']}..."):
                            success, message = create_draft(
                                from_email,
                                result["email"],
                                subject,
                                message_body,
                                result["files"],
                            )
                            results.append(
                                {
                                    "email": result["email"],
                                    "success": success,
                                    "message": message,
                                    "files": [f["filename"] for f in result["files"]],
                                }
                            )
                    else:
                        results.append(
                            {
                                "email": result["email"],
                                "success": False,
                                "message": "No matching files found",
                                "files": [],
                            }
                        )

                    # Update progress
                    progress_bar.progress((i + 1) / len(matching_results))

                # Display results
                st.subheader("Results")
                for result in results:
                    if result["success"]:
                        files_text = ", ".join(result["files"])
                        st.success(
                            f"{result['message']} with attachments: {files_text}"
                        )
                    else:
                        st.error(result["message"])
