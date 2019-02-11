# NOTE: Run as sudo to read from docker output
# TODO: Replace print(s) with logger
import os
import uuid
import docker
import flask
from flask import jsonify
import shutil
import time
app = flask.Flask(__name__)

# Prepare our docker setup
client = docker.from_env()
# TODO: Prepull image?
# client.images.pull('adferrand/letsencrypt-dns')

# TODO: Make configurable with argparse?
cert_folder = "certs"
keep_time = 60*30


def valid_uuid(potential_uuid, version=4):
    """Check if potential_uuid is a valid UUID."""
    try:
        uuid_obj = uuid.UUID(potential_uuid, version=version)
    except:
        print "Failed parsing " + potential_uuid + " to uuid"
        return False
    return str(uuid_obj) == potential_uuid


@app.route('/')
def hello_world():
    return 'Letswild!'


def clean_job(job_identifier):
    """Clean up everything we know about :code:`job_identifier`.
    
    We assume :code:`job_identifier` has already been checked.
    """
    # Delete the container
    try:
        container = client.containers.get(job_identifier)
        container.remove(v=True, force=True)
    except docker.errors.NotFound:
        print "Container not found!"
    # Delete the entire folder tree
    shutil.rmtree(cert_folder + '/' + job_identifier + '/', ignore_errors=True)


@app.route('/clean')
def clean():
    """Clean up old containers and folders."""
    # Check all folders
    for item in os.listdir(cert_folder + '/'):
        # Get time of current folder
        # TODO: Handle missing domains.conf file / check dir instead of file?
        timestamp = os.path.getmtime(cert_folder + '/' + item + '/domains.conf')
        time_since_change = (time.time() - timestamp)
        # Purge everything older than keep_time
        if time_since_change > keep_time:
            print "Purging " + item + "( age=" + str(time_since_change) + ")"
            clean_job(item)
        else:
            print "Keeping " + item + "( age=" + str(time_since_change) + ")"
    return jsonify({"state": "clean up complete"})


@app.route('/download/<job_identifier>')
def download(job_identifier):
    """Download a zip-file containing the certificate.
    
    Note: Should only be called once /certificates/ report state='done'
    """
    # Validate job_identifier is a uuid4
    if not valid_uuid(job_identifier):
        return jsonify({"error": "invalid job identifier"})

    folder_path = cert_folder + "/" + job_identifier
    cert_path = folder_path + "/live/"
    folder_abs_path = os.path.abspath(folder_path)
    cert_abs_path = os.path.abspath(cert_path)
    zip_filename_no_extension = 'certs'
    zip_filename = zip_filename_no_extension + '.zip'
    zip_abs_path_no_extension = folder_abs_path + '/' + zip_filename_no_extension
    zip_abs_path = zip_abs_path_no_extension + '.zip'

    if not os.path.isdir(folder_abs_path):
        return jsonify({"error": "folder not found"})

    if not os.path.isfile(zip_abs_path):
        # TODO: Check certificate is there, instead of making empty zip?
        # Make our archive
        shutil.make_archive(
            zip_abs_path_no_extension,
            'zip',
            cert_abs_path
        )

    try:
        # TODO: Serve zips via nginx?
        return flask.send_file(zip_abs_path, attachment_filename=zip_filename)
    except Exception as e:
        return jsonify({"error": "unable to return zip"})


@app.route('/certificate/<job_identifier>', methods=['GET'])
def handle_get(job_identifier):
    """Get status of a current job."""
    # TODO: Check if folder exists with cert, and report done?
    # Validate job_identifier is a uuid4
    if not valid_uuid(job_identifier):
        return jsonify({"error": "invalid job identifier"})
    # Try to find container
    try:
        container = client.containers.get(job_identifier)
    except docker.errors.NotFound:
        return jsonify({"error": "container not found"})
    # These are the error stages we can be in
    error_steps = [
        {
            'identifier': 'You should register before running non-interactively',
            'state': 'invalid email',
        },
        {
            'identifier': 'Error output from',
            'state': 'generic error',
        },
        {
            'identifier': 'too many certificates already issued for exact set of domains',
            'state': 'throttled by letsencrypt'
        },
    ]

    # These are the different stages we can be in
    steps = [
        {
            'identifier': 'Congratulations! Your certificate and chain',
            'state': 'done',
        },
        {
            'identifier': 'Output from cleanup.sh',
            'state': 'cleanup',
        },
        {
            'identifier': 'Waiting for verification...',
            'state': 'verification',
        },
        {
            'identifier': 'Output from authenticator.sh',
            'state': 'authenticating',
        },
        {
            'identifier': 'Obtaining a new certificate',
            'state': 'starting',
        },
        {
            'identifier': 'Creating a certificate for domain(s)',
            'state': 'detecting',
        },
    ]
    logs = container.logs()
    for index, item in enumerate(error_steps):
        if item['identifier'] in logs:
            return jsonify({"error": item['state'], "code": index})

    num_steps = len(steps)
    for index, item in enumerate(steps):
        if item['identifier'] in logs:
            return jsonify({"state": item['state'], "progress": (num_steps - index), "max": num_steps})
    return 'Unable to determine state!'


@app.route('/certificate/', methods=['POST'])
def handle_post():
    """Start a certificate job in a docker container.

    Example request:
    .. code:

        {
            "email": "emil@magenta.dk",
            "domains": [
                "*.example.com",
                "example.com"
            ],
            "dns-provider": "godaddy",
            "auth": {
                "auth_secret": "SECRET_KEY",
                "auth_key": "AUTH_TOKEN"
            }
        }

    With curl, assuming the above is in :code:`test.json`:
        curl -X POST -H "Content-Type: application/json" -d @test.json URI

    Example reply:
    .. code:

        {
            "job_identifier": "c91095e5-0162-4d38-9f78-fdac64843509"
        }

    """
    # Pull out json
    content = flask.request.json
    if not content:
        return jsonify({"error": "json not provided"})
    if 'dns-provider' not in content:
        return jsonify({"error": "json missing 'dns-provider'"})
    if 'email' not in content:
        return jsonify({"error": "json missing 'email'"})
    if 'domains' not in content:
        return jsonify({"error": "json missing 'domains' section"})
    if 'auth' not in content:
        return jsonify({"error": "json missing 'auth' section"})

    environ = {}
    # TODO: Validate email looks correct
    environ['LETSENCRYPT_USER_MAIL'] = content['email']
    # TODO: Validate provider
    environ['LEXICON_PROVIDER'] = content['dns-provider']
    # Add authentification environmental variables
    # TODO: Validate authenficiation
    for key, value in content['auth'].items():
        environ['LEXICON_' + content['dns-provider'].upper() + "_" + key.upper()] = value

    # Create output folder
    job_identifier = str(uuid.uuid4())
    folder_path = cert_folder + "/" + job_identifier
    folder_abs_path = os.path.abspath(folder_path)
    os.mkdir(folder_path)

    # TODO: Validate domain-name
    domains = " ".join(content['domains'])
    # Write domains file
    with open(folder_abs_path + '/domains.conf', 'w') as f:
        f.write(domains + "\n")

    # Fire up container
    client.containers.run(
        "adferrand/letsencrypt-dns",
        name=job_identifier,
        detach=True,
        volumes={
            folder_abs_path: {'bind': '/etc/letsencrypt', 'mode': 'rw'}
        },
        environment=environ,
    )

    # Return ID
    return jsonify({"job_identifier": job_identifier})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
