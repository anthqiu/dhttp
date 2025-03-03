from flask import Flask, request, Response

app = Flask(__name__)


@app.route('/', methods=['POST'])
def process_text():
    raw_data = request.get_data()  # Get the raw request body
    raw_headers = dict(request.headers)  # Get the request headers
    raw_method = request.method  # Get the request method
    raw_url = request.url  # Get the full URL

    print(f"Method: {raw_method}")
    print(f"URL: {raw_url}")
    print(f"Headers: {raw_headers}")
    print(f"Raw Body: {raw_data.decode('utf-8')}")

    # Check if an uploaded file exists
    if 'file' not in request.files:
        return Response("No file provided", status=400)

    file = request.files['file']

    # Check if a file is selected
    if file.filename == '':
        return Response("No file selected", status=400)

    try:
        # Read and decode the file content
        text = file.read().decode('utf-8')
    except Exception as e:
        return Response(f"File read error: {e}", status=400)

    # Replace all periods with exclamation marks, question marks with ellipsis, and commas with question marks
    modified_text = text.replace(".", "!")
    modified_text = modified_text.replace("?", "…")
    modified_text = modified_text.replace(",", "?")

    return Response(modified_text, mimetype='text/plain')


if __name__ == '__main__':
    # Run the Flask development server
    app.run(host='0.0.0.0', debug=True, port=7000)
