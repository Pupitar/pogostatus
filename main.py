import time
import yaml
import MySQLdb as msd
import pyramid.httpexceptions as exc

from threading import Lock
from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.view import view_config, forbidden_view_config, notfound_view_config
from pyramid.response import Response
from pyramid.renderers import render_to_response


class ApiCheckTimer(object):
    def __init__(self, timeouts, Lock=Lock):
        self.last_api_check = int(time.time())
        self.boot_time = int(time.time())
        self.timeouts = timeouts
        self.lock = Lock()

    def get_uptime_sec(self):
        return int(time.time()) - self.boot_time

    def get_uptime_human(self):
        output = ""
        mins, secs = divmod(self.get_uptime_sec(), 60)
        hours, mins = divmod(mins, 60)
        days, hours = divmod(hours, 24)

        if days and days == 1:
            output += f"{days} day "
        elif days:
            output += f"{days} days "

        output += f"{hours:02}:{mins:02}:{secs:02}"

        return output

    def set_now(self):
        with self.lock:
            self.last_api_check = int(time.time())

    def sec_from_last(self):
        return int(time.time()) - self.last_api_check


@forbidden_view_config(renderer='json')
def forbidden(request):
    request.response.status = 403
    return {"status": False, "message": "access denied"}


@notfound_view_config(renderer='json')
def not_found(request):
    request.response.status = 404
    return {"status": False, "message": "not found"}


def is_hidden(device_name, instance_name):
    return app_config["ignore"]["hidden_device_pattern"] and any([
        device_name.startswith(hidden_device)
        for hidden_device
        in app_config["ignore"]["hidden_device_pattern"]
    ]) or app_config["ignore"]["hidden_instance_pattern"] and any([
        instance_name.startswith(hidden_instance)
        for hidden_instance
        in app_config["ignore"]["hidden_instance_pattern"]
    ])


def name_overwrite(device_name, instance_name):
    if app_config["device_name_overwrite"]:
        for origin, target in app_config["device_name_overwrite"]:
            device_name = device_name.replace(origin, target)

    if app_config["instance_name_overwrite"]:
        for origin, target in app_config["instance_name_overwrite"]:
            instance_name = instance_name.replace(origin, target)

    return device_name, instance_name


def get_pub_data(hidden=False):
    output = {}
    tmp_data = fetch_sql_data("rdm")

    if not hidden:
        for device_name in list(tmp_data.keys()):
            if not is_hidden(device_name, tmp_data[device_name]["instance_name"]):
                output[device_name] = tmp_data[device_name]
        tmp_data = output

    output = {}

    for device_name, device_data in tmp_data.items():
        device_name, instance_name = name_overwrite(device_name, device_data["instance_name"])

        output[device_name] = device_data
        output[device_name]["instance_name"] = instance_name

    return output


def fetch_sql_data(data_type):
    con, output = None, {}

    try:
        if data_type == "rdm":
            con = msd.connect(
                app_config["rdm_database"]["host"], app_config["rdm_database"]["user"],
                app_config["rdm_database"]["password"], app_config["rdm_database"]["name"],
            )
            cur = con.cursor()

            cur.execute("""
                SELECT
                    uuid, UNIX_TIMESTAMP() - last_seen, last_seen, instance_name
                FROM device
                ORDER BY `uuid` ASC
            """)

            output = {
                n[0]: {
                    "last_seen_from_now": n[1],
                    "last_seen": n[2],
                    "instance_name": n[3]
                } for n in cur.fetchall()
            }

            con.close()

        elif data_type == "dcm":
            con = msd.connect(
                app_config["dcm_database"]["host"], app_config["dcm_database"]["user"],
                app_config["dcm_database"]["password"], app_config["dcm_database"]["name"],
            )
            cur = con.cursor()

            cur.execute("""
                SELECT
                    uuid, UNIX_TIMESTAMP() - last_seen, last_seen, model, ios_version, ipa_version, enabled
                FROM `devices`
                ORDER BY `uuid` ASC
            """)

            output = {
                n[0]: {
                    "last_heartbeat_from_now": n[1],
                    "last_heartbeat": n[2],
                    "model": n[3],
                    "ios_version": n[4],
                    "ipa_version": n[5],
                    "enabled": n[6],
                } for n in cur.fetchall()
            }

            con.close()

    except Exception:
        return output

    return output


@view_config(route_name='api', renderer='json')
def api(request):
    api_key = request.headers.get("X-API-Key")
    if api_key != app_config["app"]["api_key"]:
        raise exc.HTTPForbidden()

    request.registry.api_check_timer.set_now()

    rdm_status_dict = fetch_sql_data("rdm")
    dcm_status_dict = fetch_sql_data("dcm")

    output_dict = {"devices": {}, "status": False}

    for device_name, device_data in rdm_status_dict.items():
        output_dict["devices"][device_name] = dict(device_data, **dcm_status_dict[device_name])

    if output_dict["devices"]:
        output_dict["status"] = True

    return output_dict


@view_config(route_name='status', renderer='templates/status.jinja2')
def status(request):
    if not app_config["pages"]["public_enabled"]:
        raise exc.HTTPNotFound()

    return {
        "devices": get_pub_data(hidden=False),
        "app_config": app_config,
        "last_api_check": request.registry.api_check_timer.sec_from_last(),
        "status_uptime": request.registry.api_check_timer.get_uptime_human(),
    }


@view_config(route_name='status_all', renderer='templates/status.jinja2')
def status_all(request):
    if not app_config["pages"]["hidden_enabled"]:
        raise exc.HTTPNotFound()

    return {
        "devices": get_pub_data(hidden=True),
        "app_config": app_config,
        "last_api_check": request.registry.api_check_timer.sec_from_last(),
        "status_uptime": request.registry.api_check_timer.get_uptime_human(),
    }


if __name__ == '__main__':
    app_config = yaml.safe_load(open("config.yml"))
    last_api_check = int(time.time())

    with Configurator() as config:
        config.include('pyramid_jinja2')
        config.add_route('status', '/')
        config.add_route('api', '/api')
        config.add_route('status_all', '/' + app_config["pages"]["hidden_name"])
        config.scan()
        config.registry.api_check_timer = ApiCheckTimer(timeouts=app_config["timeout"])
        app = config.make_wsgi_app()

    server = make_server(
        app_config["app"]["bind"],
        app_config["app"]["port"],
        app
    )
    server.serve_forever()
