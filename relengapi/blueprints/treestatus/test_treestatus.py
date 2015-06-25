# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from flask import json
from nose.tools import eq_
from relengapi.blueprints.treestatus import model
from relengapi.lib.testing.context import TestContext


def db_setup(app):
    session = app.db.session('treestatus')
    tree = model.DbTree()
    tree.tree = 'tree1'
    session.add(tree)
    session.commit()


test_context = TestContext(databases=['treestatus'], db_setup=db_setup)


@test_context
def test_treestatus(client):
    """Getting /treestatus/?format=json should return a dictionary with tree status info"""
    resp = client.get('/treestatus/?format=json')
    eq_(json.loads(resp.data),
        {'tree1': {'status': 'open',
                   'message_of_the_day': '',
                   'tree': 'tree1',
                   'reason': ''}})
