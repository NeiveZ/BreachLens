from breachlens.modules.passwords import sha1_upper


def test_sha1_upper_known_value():
    assert sha1_upper("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
