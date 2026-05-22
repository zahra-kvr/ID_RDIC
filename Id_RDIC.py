import hashlib
import random
from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR, pair

# ==========================================
# CRYPTOGRAPHIC ENGINE (Symmetric SS512)
# Based on: Identity-based remote data integrity
# checking with perfect data privacy preserving
# for cloud storage - Yong Yu et al.
# ==========================================
class CryptographicEngine:
    def __init__(self):
        # e: G1 x G1 -> GT
        self.group = PairingGroup('SS512')
        self.g = self.group.random(G1)

    def Hash1(self, identity_string):
        # generates client's secret key
        return self.group.hash(identity_string, G1)

    def Hash2(self, block_metadata_string):
        # used for tag generation
        return self.group.hash(block_metadata_string, G1)

    def Hash3(self, gt_element):
        # used for proof check
        serialized = self.group.serialize(gt_element)
        return hashlib.sha256(serialized).hexdigest()


crypto = CryptographicEngine()


# ==========================================
# KGC, CLIENT, AND SERVER MODULES
# ==========================================
class KeyGenerationCenter:
    def __init__(self):
        self.master_secret_key = None
        self.public_params = {}

    def Setup(self):
        self.master_secret_key = crypto.group.random(ZR)
        P_pub = crypto.g ** self.master_secret_key
        self.public_params = {
            'g': crypto.g,
            'P_pub': P_pub
        }
        return self.public_params

    def Extract(self, client_identity):
        if self.master_secret_key is None:
            raise Exception("KGC Setup must be run first.")
        h1_id = crypto.Hash1(client_identity)
        secret_key =  h1_id **(self.master_secret_key)
        return secret_key


class Client:
    def __init__(self, identity, public_params, secret_key=None):
        self.identity = identity
        self.public_params = public_params
        self.secret_key = secret_key

    def SegmentFile(self, file_bytes, block_size=1024):
        blocks = []
        for i in range(0, len(file_bytes), block_size):
            chunk = file_bytes[i:i+block_size]
            int_val = int.from_bytes(chunk, byteorder='big')
            field_element = crypto.group.init(ZR, int_val % crypto.group.order())
            blocks.append(field_element)
        return blocks

    def TagGen(self, file_id, blocks):
        if not self.secret_key:
            raise Exception("Secret key is missing.")

        eta = crypto.group.random(ZR)
        r = crypto.g ** eta
        tags = []
        for index, m_i in enumerate(blocks):
            metadata = f"{file_id}{index}"
            H2_val = crypto.Hash2(metadata)
            sigma_i = (self.secret_key ** m_i)*(H2_val**eta)
            tags.append(sigma_i)

        return tags, r

    def Challenge(self, total_blocks, sampling_size):
        challenged_indices = random.sample(range(total_blocks), min(sampling_size, total_blocks))
        challenge_query = {}
        for index in challenged_indices:
            v_i = crypto.group.random(ZR)
            challenge_query[index] = v_i

        rho = crypto.group.random(ZR)
        h1_id = crypto.Hash1(self.identity)
        Z = pair(h1_id, self.public_params['P_pub'])
        c1 = crypto.g ** rho
        c2 = Z ** rho

        return challenge_query, rho, c1, c2

    def CheckProof(self, challenge_query, response, rho):
        m_prime = response['m_prime']
        r = response['r']
        file_id = response['file_id']

        aggregated_e = None
        for index, v_i in challenge_query.items():
            metadata = f"{file_id}{index}"
            H2_val = crypto.Hash2(metadata)
            term = H2_val ** v_i
            r_rho = r ** rho
            e_sigma= pair(term, r_rho)
            if aggregated_e is None:
                aggregated_e = e_sigma
            else:
                aggregated_e *= e_sigma
      
        left = crypto.Hash3(aggregated_e)
        return left == m_prime


class RemoteCloudServer:
    def __init__(self):
        self.storage_vault = {}

    def StoreData(self, file_id, blocks, tags, r, owner_identity):
        self.storage_vault[file_id] = {
            'blocks': blocks,
            'tags': tags,
            'r': r,
            'owner': owner_identity
        }

    def DeleteFile(self, file_id):
        if file_id in self.storage_vault:
            del self.storage_vault[file_id]
            return True
        return False

    def GenerateProof(self, file_id, challenge_query, c1, c2):
        file_data = self.storage_vault.get(file_id)
        if not file_data:
            raise Exception("File not found on server.")

        blocks = file_data['blocks']
        tags = file_data['tags']

        mu = None
        sigma = None
        for index, v_i in challenge_query.items():
            m_i = blocks[index]
            sigma_i = tags[index]

            tag_term = sigma_i ** v_i
            mu_i = m_i * v_i

            if sigma is None:
                sigma = tag_term
            else:
                sigma *= tag_term

            if mu is None:
                mu = mu_i
            else:
                mu += mu_i

        e_sigma_c1 = pair(sigma, c1)
        c2_mu = c2 ** mu
        combined = e_sigma_c1 * (c2_mu ** -1)
        m_prime = crypto.Hash3(combined)

        return {'m_prime': m_prime, 'r': file_data['r'], 'file_id': file_id}


# ==========================================
# BATCH AUDIT ALL FILES
# ==========================================
def BatchAudit(server, public_params, sampling_size=3):
    results = {}
    for file_id, file_data in server.storage_vault.items():
        total_blocks = len(file_data['blocks'])
        challenged_indices = random.sample(range(total_blocks), min(sampling_size, total_blocks))
        challenge_query = {}
        for idx in challenged_indices:
            challenge_query[idx] = crypto.group.random(ZR)

        owner_identity = file_data['owner']
        rho = crypto.group.random(ZR)
        h1_id = crypto.Hash1(owner_identity)
        Z = pair(h1_id, public_params['P_pub'])
        c1 = public_params['g'] ** rho
        c2 = Z ** rho

        proof = server.GenerateProof(file_id, challenge_query, c1, c2)

        aggregated_e = None
        for index, v_i in challenge_query.items():
            metadata = f"{file_id}{index}"
            H2_val = crypto.Hash2(metadata)
            term = H2_val ** v_i
            r_rho = file_data['r'] ** rho
            e_val = pair(term, r_rho)
            if aggregated_e is None:
                aggregated_e = e_val
            else:
                aggregated_e *= e_val

        left = crypto.Hash3(aggregated_e)
        results[file_id] = left == proof['m_prime']

    return results


# ==========================================
# TEXTUAL TUI
# ==========================================
from textual.app import App
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, Input, Label, Rule
from textual.screen import Screen, ModalScreen
from textual.binding import Binding
from textual import on


def get_key_hex(private_key):
    zr_bytes = crypto.group.serialize(private_key)
    return zr_bytes.hex()


def parse_key(raw_key_str, identity=None):
    key_bytes = bytes.fromhex(raw_key_str)
    return crypto.group.deserialize(key_bytes)


class InputModal(ModalScreen):
    BINDINGS = [Binding("q", "quit", "Quit", show=True)]

    def __init__(self, title, fields):
        super().__init__()
        self.modal_title = title
        self.fields = fields

    def compose(self):
        yield Container(
            Label(self.modal_title, id="modal-title"),
            *[Input(placeholder=f["placeholder"], password=f.get("password", False), id=f["id"]) for f in self.fields],
            Horizontal(
                Button("Cancel", variant="default", id="modal-cancel"),
                Button("Submit", variant="primary", id="modal-submit"),
                id="modal-buttons"
            ),
            id="modal-container"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "modal-cancel":
            self.dismiss(None)
        elif event.button.id == "modal-submit":
            values = {}
            for f in self.fields:
                inp = self.query_one(f"#{f['id']}", Input)
                values[f["id"]] = inp.value.strip()
            self.dismiss(values)

    @on(Input.Submitted)
    def on_submit(self, event: Input.Submitted):
        self.post_message(Button.Pressed(self.query_one("#modal-submit", Button)))


class ResultModal(ModalScreen):
    BINDINGS = [Binding("q", "quit", "Quit", show=True)]

    def __init__(self, title, message, success=True):
        super().__init__()
        self.modal_title = title
        self.modal_message = message
        self.modal_success = success

    def compose(self):
        status = "[#00ff88]SUCCESS[/#00ff88]" if self.modal_success else "[#ff4466]FAILURE[/#ff4466]"
        yield Container(
            Label(f"{self.modal_title}  {status}", id="modal-title"),
            Static(self.modal_message, id="modal-message"),
            Horizontal(
                Button("OK", variant="primary", id="modal-ok"),
                id="modal-buttons"
            ),
            id="modal-container"
        )

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss()


class ConfirmModal(ModalScreen):
    BINDINGS = [Binding("q", "quit", "Quit", show=True)]

    def __init__(self, title, message):
        super().__init__()
        self.modal_title = title
        self.modal_message = message

    def compose(self):
        yield Container(
            Label(self.modal_title, id="modal-title"),
            Static(self.modal_message, id="modal-message"),
            Horizontal(
                Button("Cancel", variant="default", id="modal-cancel"),
                Button("Confirm", variant="error", id="modal-confirm"),
                id="modal-buttons"
            ),
            id="modal-container"
        )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "modal-confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)


class MainScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit", show=True),
    ]

    def __init__(self, kgc, public_params, server, key_cache):
        super().__init__()
        self.kgc = kgc
        self.public_params = public_params
        self.server = server
        self.key_cache = key_cache

    def compose(self):
        yield Header(show_clock=True)
        with Horizontal(id="app-layout"):
            with Vertical(id="sidebar"):
                yield Label("  ACTIONS", id="sidebar-title")
                yield Button("  Extract Private Key", id="btn-extract", variant="default")
                yield Button("  Upload & Sign File", id="btn-upload", variant="default")
                yield Button("  Audit Single File", id="btn-audit", variant="default")
                yield Button("  Batch Audit All", id="btn-batch", variant="default")
                yield Button("  Corrupt Storage", id="btn-corrupt", variant="default")
                yield Button("  Delete File", id="btn-delete", variant="default")
            with ScrollableContainer(id="main-panel"):
                yield Static("", id="output")
        yield Footer()

    def refresh_output(self, content):
        self.query_one("#output", Static).update(content)

    def show_result(self, title, message, success=True):
        def on_dismiss(result):
            pass
        self.app.push_screen(ResultModal(title, message, success), on_dismiss)

    def show_confirm(self, title, message, callback):
        def on_dismiss(result):
            if result:
                callback()
        self.app.push_screen(ConfirmModal(title, message), on_dismiss)

    def show_input(self, title, fields, callback):
        def on_dismiss(values):
            if values:
                callback(values)
        self.app.push_screen(InputModal(title, fields), on_dismiss)

    @on(Button.Pressed)
    def on_button(self, event: Button.Pressed):
        btn_id = event.button.id

        if btn_id == "btn-extract":
            self.show_input("Extract Private Key", [
                {"id": "identity", "placeholder": "User Identity"}
            ], self._do_extract)

        elif btn_id == "btn-upload":
            self.show_input("Upload & Sign File", [
                {"id": "identity", "placeholder": "User Identity"},
                {"id": "file_id", "placeholder": "File Name"},
                {"id": "content", "placeholder": "File Content"}
            ], self._do_upload)

        elif btn_id == "btn-audit":
            self._do_audit()

        elif btn_id == "btn-batch":
            self._do_batch_audit()

        elif btn_id == "btn-corrupt":
            self._do_corrupt()

        elif btn_id == "btn-delete":
            self._do_delete()

    def _do_extract(self, values):
        identity = values.get("identity", "")
        if not identity:
            self.show_result("Error", "Identity cannot be empty.", success=False)
            return
        try:
            private_key = self.kgc.Extract(identity)
            self.key_cache[identity] = private_key
            key_hex = get_key_hex(private_key)
            self.show_result("Key Generated", f"Identity: {identity}\n\nPrivate Key:\n{key_hex}", success=True)
        except Exception as e:
            self.show_result("Error", str(e), success=False)

    def _do_upload(self, values):
        identity = values.get("identity", "")
        file_id = values.get("file_id", "")
        content = values.get("content", "")

        if not identity or not file_id or not content:
            self.show_result("Error", "All fields are required.", success=False)
            return

        def on_key_input(vals):
            raw = vals.get("key", "") if vals else ""
            if not raw:
                self.show_result("Error", "Secret key is required to create tags.", success=False)
                return
            if identity not in self.key_cache:
                self.show_result("Error", f"Identity '{identity}' is not registered. Extract a key first.", success=False)
                return
            try:
                key_el = parse_key(raw, identity)
                cached_key = self.key_cache[identity]
                if crypto.group.serialize(key_el) != crypto.group.serialize(cached_key):
                    self.show_result("Error", "Provided key does not match the registered identity.", success=False)
                    return
                self._complete_upload(identity, file_id, content, key_el)
            except Exception as e:
                self.show_result("Error", f"Invalid key: {e}", success=False)

        self.show_input("Enter Secret Key", [
            {"id": "key", "placeholder": "Paste secret key hex string"}
        ], on_key_input)

    def _complete_upload(self, identity, file_id, content, key_element):
        try:
            client = Client(identity=identity, public_params=self.public_params, secret_key=key_element)
            blocks = client.SegmentFile(content.encode('utf-8'), block_size=4)
            tags, r = client.TagGen(file_id, blocks)
            self.server.StoreData(file_id, blocks, tags, r, owner_identity=identity)
            self.show_result("Upload Complete", f"File '{file_id}' uploaded with {len(blocks)} blocks.\nRandom value r generated for privacy.", success=True)
        except Exception as e:
            self.show_result("Error", str(e), success=False)

    def _do_audit(self):
        if not self.server.storage_vault:
            self.show_result("Empty", "No files on the server.", success=False)
            return

        files = list(self.server.storage_vault.keys())

        def on_audit_input(values):
            file_id = values.get("file_id", "")
            identity = values.get("identity", "")
            sample_str = values.get("sample", "")

            if not file_id or not identity:
                self.show_result("Error", "File and identity are required.", success=False)
                return
            if file_id not in self.server.storage_vault:
                self.show_result("Error", f"File '{file_id}' not found.", success=False)
                return
            if identity not in self.key_cache:
                self.show_result("Error", f"Identity '{identity}' is not registered. Extract a key first.", success=False)
                return
            if self.server.storage_vault[file_id]['owner'] != identity:
                self.show_result("Error", f"Identity '{identity}' does not match the file owner '{self.server.storage_vault[file_id]['owner']}'.", success=False)
                return

            total = len(self.server.storage_vault[file_id]['blocks'])
            default_sample = max(1, int(total * 0.3))
            sampling_size = int(sample_str) if sample_str.isdigit() else default_sample

            try:
                client = Client(identity=identity, public_params=self.public_params)
                challenge_query, rho, c1, c2 = client.Challenge(total, sampling_size=sampling_size)
                proof = self.server.GenerateProof(file_id, challenge_query, c1, c2)
                is_valid = client.CheckProof(challenge_query, proof, rho)

                indices = list(challenge_query.keys())
                if is_valid:
                    self.show_result("Audit Passed",
                        f"File: {file_id}\nIndices checked: {indices}\nBlocks sampled: {sampling_size}\n\nData is intact and identity verified.",
                        success=True)
                else:
                    self.show_result("Audit Failed",
                        f"File: {file_id}\nIndices checked: {indices}\n\nMismatched identity or corrupted data detected.",
                        success=False)
            except Exception as e:
                self.show_result("Error", str(e), success=False)

        self.show_input("Audit File", [
            {"id": "file_id", "placeholder": f"File name ({', '.join(files)})"},
            {"id": "identity", "placeholder": "File owner identity"},
            {"id": "sample", "placeholder": f"Sample size (default: 30%)"}
        ], on_audit_input)

    def _do_batch_audit(self):
        if not self.server.storage_vault:
            self.show_result("Empty", "No files on the server.", success=False)
            return

        try:
            results = BatchAudit(self.server, self.public_params, sampling_size=3)
            summary = "\n".join(
                f"  {'PASS' if v else 'FAIL'}  {fid}"
                for fid, v in results.items()
            )
            all_pass = all(results.values())
            self.show_result("Batch Audit Results",
                f"Audited {len(results)} file(s):\n\n{summary}",
                success=all_pass)
        except Exception as e:
            self.show_result("Error", str(e), success=False)

    def _do_corrupt(self):
        if not self.server.storage_vault:
            self.show_result("Empty", "No files to corrupt.", success=False)
            return

        files = list(self.server.storage_vault.keys())

        def on_corrupt_input(values):
            file_id = values.get("file_id", "")
            block_idx_str = values.get("block_idx", "")

            if not file_id or file_id not in self.server.storage_vault:
                self.show_result("Error", f"File '{file_id}' not found.", success=False)
                return

            blocks_list = self.server.storage_vault[file_id]['blocks']
            max_idx = len(blocks_list) - 1

            if not block_idx_str.isdigit() or int(block_idx_str) > max_idx:
                self.show_result("Error", f"Invalid block index (0-{max_idx}).", success=False)
                return

            block_idx = int(block_idx_str)
            corruption_offset = crypto.group.random(ZR)
            blocks_list[block_idx] += corruption_offset
            self.show_result("Corruption Complete", f"Block {block_idx} of '{file_id}' has been corrupted.", success=True)

        self.show_input("Corrupt File Storage", [
            {"id": "file_id", "placeholder": f"File name ({', '.join(files)})"},
            {"id": "block_idx", "placeholder": f"Block index (0-{len(self.server.storage_vault[files[0]]['blocks'])-1})"}
        ], on_corrupt_input)

    def _do_delete(self):
        if not self.server.storage_vault:
            self.show_result("Empty", "No files to delete.", success=False)
            return

        files = list(self.server.storage_vault.keys())

        def on_delete_input(values):
            file_id = values.get("file_id", "")
            if not file_id or file_id not in self.server.storage_vault:
                self.show_result("Error", f"File '{file_id}' not found.", success=False)
                return

            def do_delete():
                self.server.DeleteFile(file_id)
                self.show_result("Deleted", f"File '{file_id}' has been removed.", success=True)

            self.show_confirm("Confirm Delete", f"Are you sure you want to delete '{file_id}'?", do_delete)

        self.show_input("Delete File", [
            {"id": "file_id", "placeholder": f"File name ({', '.join(files)})"}
        ], on_delete_input)


class AuditApp(App):
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]

    CSS = """
    Screen {
        background: #0a0e17;
    }

    #app-layout {
        height: 1fr;
    }

    #sidebar {
        width: 30;
        background: #0d1025;
        border-right: thick #6c5ce7;
        padding: 1 2;
    }

    #sidebar-title {
        color: #6c5ce7;
        text-style: bold;
        margin: 1 0 1 0;
        text-align: center;
    }

    #sidebar Button {
        width: 100%;
        margin: 1 0;
        background: #1e2340;
        border: tall #2d3460;
    }

    #sidebar Button:hover {
        background: #2d3460;
        border: tall #6c5ce7;
    }

    #sidebar Button:focus {
        background: #3d4480;
        border: tall #a29bfe;
    }

    #main-panel {
        width: 1fr;
        padding: 1 2;
        background: #0a0e17;
    }

    #output {
        content-align: center middle;
        color: #636e85;
    }

    #modal-container {
        align: center middle;
        width: 60;
        height: auto;
        max-height: 20;
        background: #1a1f35;
        border: tall #6c5ce7;
        padding: 1 2;
    }

    #modal-title {
        text-style: bold;
        color: #6c5ce7;
        margin-bottom: 1;
    }

    #modal-message {
        margin: 1 0;
        color: #b2bec3;
    }

    #modal-buttons {
        align: center middle;
        margin-top: 1;
    }

    #modal-buttons Button {
        margin: 0 1;
        min-width: 10;
    }

    Input {
        margin: 1 0;
        border: tall #2d3460;
    }

    Input:focus {
        border: tall #6c5ce7;
    }

    Header {
        background: #1a1f35;
        color: #6c5ce7;
    }

    Footer {
        background: #1a1f35;
        color: #636e85;
    }
    """

    def on_mount(self):
        self.kgc = KeyGenerationCenter()
        self.public_params = self.kgc.Setup()
        self.server = RemoteCloudServer()
        self.key_cache = {}
        self.push_screen(MainScreen(self.kgc, self.public_params, self.server, self.key_cache))


if __name__ == "__main__":
    app = AuditApp()
    app.run()
