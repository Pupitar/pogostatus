import MySQLdb as msd
import pyramid.httpexceptions as exc
import sys
import time
import yaml
from pyramid.config import Configurator
from pyramid.view import view_config, forbidden_view_config, notfound_view_config
from threading import Lock
from wsgiref.simple_server import make_server

required_dcm_db = 14


class PokeTimer(object):
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


class PokeDB:
    def __init__(self, db_type):
        self.con = msd.connect(
            host=app_config[db_type]["host"],
            user=app_config[db_type]["user"],
            passwd=app_config[db_type]["password"],
            db=app_config[db_type]["name"],
            connect_timeout=app_config[db_type]["connect_timeout"],
        )
        self.cursor = self.con.cursor()

    def execute(self, query):
        self.cursor.execute(query)

    def fetchall(self):
        return self.cursor.fetchall()

    def fetch_row(self):
        return self.cursor.fetchone()

    def close(self):
        if self.con:
            self.con.close()


@forbidden_view_config(renderer='json')
def forbidden(request):
    request.response.status = 403
    return {"status": False, "message": "access denied"}


@notfound_view_config(renderer='json')
def not_found(request):
    request.response.status = 404
    return {"status": False, "message": "not found"}


def is_hidden(device_name, instance_name):
    return not instance_name or app_config["ignore"]["hidden_device_pattern"] and any([
        device_name.startswith(hidden_device)
        for hidden_device
        in app_config["ignore"]["hidden_device_pattern"]
    ]) or app_config["ignore"]["hidden_instance_pattern"] and any([
        instance_name.startswith(hidden_instance)
        for hidden_instance
        in app_config["ignore"]["hidden_instance_pattern"]
    ])


def init_check():
    db = PokeDB("dcm_database")
    db.execute("SELECT `value` FROM `metadata` WHERE `key` = 'DB_VERSION';")
    dcm_version = int(db.fetch_row()[0])
    db.close()

    if required_dcm_db > dcm_version:
        print(f"Supported DCM db schema: {required_dcm_db}")
        sys.exit(1)


def name_overwrite(device_name, instance_name):
    if app_config["device_name_overwrite"]:
        for origin, target in app_config["device_name_overwrite"]:
            device_name = (device_name or "").replace(origin, target)

    if app_config["instance_name_overwrite"]:
        for origin, target in app_config["instance_name_overwrite"]:
            instance_name = (instance_name or "").replace(origin, target)

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
        output[device_name]["always_ok"] = bool(any([
            device_data["instance_name"].startswith(i)
            for i in app_config.get("always_ok_status", [])
        ]))

    return output


def fetch_sql_data(data_type):
    output = {}

    try:
        if data_type == "dcm":
            db = PokeDB("dcm_database")
            db.execute("""
                SELECT
                    uuid, UNIX_TIMESTAMP() - last_seen, last_seen, model,
                    ios_version, ipa_version, enabled, exclude_reboots, clientip
                FROM `devices`
                WHERE enabled = 1
                ORDER BY `uuid` ASC
            """)

            output = {
                n[0]: {
                    "dcm_heartbeat_from_now": n[1],
                    "dcm_heartbeat": n[2],
                    "model": n[3],
                    "ios_version": n[4],
                    "ipa_version": n[5],
                    "enabled": n[6],
                    "exclude_reboots": n[7],
                    "clientip": n[8],
                } for n in db.fetchall()
            }

            db.close()

        elif data_type == "rdm":
            db = PokeDB("rdm_database")
            db.execute("""
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
                } for n in db.fetchall()
            }

            db.close()

        elif data_type == "lorg":
            db = PokeDB("lorg_database")
            db.execute("""
                SELECT
                    device_id, UNIX_TIMESTAMP() - updated, updated, instance
                FROM `accounts`
                WHERE device_id is not NULL
            """)

            output = {
                n[0]: {
                    "last_seen_from_now": n[1],
                    "last_seen": n[2],
                    "instance_name": n[3]
                } for n in db.fetchall()
            }

            db.close()

    except Exception:
        return output

    return output


@view_config(route_name='api', renderer='json')
def api(request):
    api_key = request.headers.get("X-API-Key")
    if api_key != app_config["app"]["api_key"]:
        raise exc.HTTPForbidden()

    if not request.GET.get("skip_timer"):
        request.registry.api_check_timer.set_now()

    rdm_status_dict, lorg_status_dict = None, None

    # main query
    dcm_status_dict = fetch_sql_data("dcm")

    if app_config["rdm_database"]["enabled"]:
        rdm_status_dict = fetch_sql_data("rdm")

    if app_config["lorg_database"]["enabled"]:
        lorg_status_dict = fetch_sql_data("lorg")

    output_dict = {"devices": {}, "status": False}

    for device_name, device_data in dcm_status_dict.items():
        in_backend = False
        last_seen_backend = 0

        if rdm_status_dict and device_name in rdm_status_dict.keys():
            in_backend = True
            output_dict["devices"][device_name] = dict(device_data, **rdm_status_dict[device_name])
            output_dict["devices"][device_name]["source"] = 1
            last_seen_backend = output_dict["devices"][device_name]["last_seen"]

        # overwrite if needed
        if lorg_status_dict and device_name in lorg_status_dict.keys():
            in_backend = True
            if (
                device_name in output_dict and
                output_dict[device_name]["last_seen"] > output_dict["devices"][device_name]["last_seen"]
                or device_name not in output_dict
            ):
                output_dict["devices"][device_name] = dict(device_data, **lorg_status_dict[device_name])
                output_dict["devices"][device_name]["source"] = 2
                last_seen_backend = output_dict["devices"][device_name]["last_seen"]

        if not in_backend:
            output_dict["devices"][device_name] = dict(device_data, **{
                "last_seen_from_now": device_data["dcm_heartbeat_from_now"],
                "last_seen": device_data["dcm_heartbeat"],
                "instance_name": 'No Backend'
            })
            output_dict["devices"][device_name]["source"] = 0

        # add new key uuid with device name
        output_dict["devices"][device_name]["uuid"] = device_name

        # if heartbeat > backend last seen ; replace
        if output_dict["devices"][device_name]["dcm_heartbeat"] > last_seen_backend:
            output_dict["devices"][device_name] = dict(device_data, **{
                "last_seen_from_now": device_data["dcm_heartbeat_from_now"],
                "last_seen": device_data["dcm_heartbeat"]
            })

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
    init_check()
    last_api_check = int(time.time())

    with Configurator() as config:
        config.include('pyramid_jinja2')
        config.add_route('status', '/')
        config.add_route('api', '/api')
        config.add_route('status_all', '/' + app_config["pages"]["hidden_name"])
        config.scan()
        config.registry.api_check_timer = PokeTimer(timeouts=app_config["timeout"])
        app = config.make_wsgi_app()

    server = make_server(
        app_config["app"]["bind"],
        app_config["app"]["port"],
        app
    )
    server.serve_forever()
