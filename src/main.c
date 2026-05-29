/* SPDX-License-Identifier: Apache-2.0 */

#include "sm2_tinypki.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APP_VERSION "1.1.0"
#define APP_OK(label) printf("[OK] %s\n", label)
#define APP_CHECK(cond, label)                                                \
    do                                                                         \
    {                                                                          \
        if (!(cond))                                                           \
        {                                                                      \
            fprintf(stderr, "[FAIL] %s\n", label);                            \
            return 1;                                                          \
        }                                                                      \
        APP_OK(label);                                                         \
    } while (0)

typedef struct
{
    sm2_private_key_t private_key;
    sm2_ec_point_t public_key;
    sm2_pki_transparency_witness_t meta;
} witness_slot_t;

typedef struct
{
    char site_id[64];
    char line_id[64];
    char terminal_id[64];
    char controller_id[64];
    char command[128];
    uint64_t maintenance_window_s;
    unsigned required_witnesses;
    int fail_closed;
    int json_output;
} app_config_t;

static void copy_field(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0U)
        return;
    if (!src)
        src = "";
    snprintf(dst, dst_len, "%s", src);
}

static void app_config_default(app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    copy_field(cfg->site_id, sizeof(cfg->site_id), "plant-east");
    copy_field(cfg->line_id, sizeof(cfg->line_id), "line-ctrl-07");
    copy_field(cfg->terminal_id, sizeof(cfg->terminal_id), "MAINT-TERMINAL-17");
    copy_field(cfg->controller_id, sizeof(cfg->controller_id), "LINE-CTRL-07");
    copy_field(cfg->command, sizeof(cfg->command),
        "maintenance:open-panel:line-ctrl-07");
    cfg->maintenance_window_s = 900U;
    cfg->required_witnesses = 2U;
    cfg->fail_closed = 1;
}

static char *trim(char *s)
{
    char *end = NULL;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    if (*s == '\0')
        return s;
    end = s + strlen(s) - 1U;
    while (end > s
        && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
    {
        *end = '\0';
        end--;
    }
    return s;
}

static int parse_bool(const char *value, int *out)
{
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0
        || strcmp(value, "yes") == 0)
    {
        *out = 1;
        return 1;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0
        || strcmp(value, "no") == 0)
    {
        *out = 0;
        return 1;
    }
    return 0;
}

static int load_config(const char *path, app_config_t *cfg)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    if (!fp)
    {
        fprintf(stderr,
            "[WARN] config file '%s' not found; using built-in safe defaults\n",
            path);
        return 1;
    }
    while (fgets(line, sizeof(line), fp))
    {
        char *key = trim(line);
        char *eq = NULL;
        char *value = NULL;
        if (*key == '\0' || *key == '#')
            continue;
        eq = strchr(key, '=');
        if (!eq)
        {
            fclose(fp);
            fprintf(stderr, "[FAIL] invalid config line: %s\n", key);
            return 0;
        }
        *eq = '\0';
        key = trim(key);
        value = trim(eq + 1);
        if (strcmp(key, "site_id") == 0)
            copy_field(cfg->site_id, sizeof(cfg->site_id), value);
        else if (strcmp(key, "line_id") == 0)
            copy_field(cfg->line_id, sizeof(cfg->line_id), value);
        else if (strcmp(key, "terminal_id") == 0)
            copy_field(cfg->terminal_id, sizeof(cfg->terminal_id), value);
        else if (strcmp(key, "controller_id") == 0)
            copy_field(cfg->controller_id, sizeof(cfg->controller_id), value);
        else if (strcmp(key, "command") == 0)
            copy_field(cfg->command, sizeof(cfg->command), value);
        else if (strcmp(key, "maintenance_window_s") == 0)
            cfg->maintenance_window_s = strtoull(value, NULL, 10);
        else if (strcmp(key, "required_witnesses") == 0)
            cfg->required_witnesses = (unsigned)strtoul(value, NULL, 10);
        else if (strcmp(key, "fail_closed") == 0)
        {
            if (!parse_bool(value, &cfg->fail_closed))
            {
                fclose(fp);
                fprintf(stderr, "[FAIL] invalid fail_closed value: %s\n",
                    value);
                return 0;
            }
        }
        else
            fprintf(stderr, "[WARN] ignored config key: %s\n", key);
    }
    fclose(fp);
    return 1;
}

static void print_usage(const char *argv0)
{
    printf("EdgeAccessPKI %s\n", APP_VERSION);
    printf("Usage: %s [--config PATH] [--json] [--version]\n", argv0);
    printf("Default config: config/gateway.conf\n");
}

static int init_witness(witness_slot_t *slot, const char *id)
{
    if (!slot || !id)
        return 0;
    memset(slot, 0, sizeof(*slot));
    if (sm2_pki_generate_ephemeral_keypair(&slot->private_key, &slot->public_key)
        != SM2_PKI_SUCCESS)
        return 0;
    size_t id_len = strlen(id);
    if (id_len > sizeof(slot->meta.witness_id))
        return 0;
    memcpy(slot->meta.witness_id, id, id_len);
    slot->meta.witness_id_len = id_len;
    slot->meta.key_version = SM2_PKI_WITNESS_KEY_DEFAULT_VERSION;
    slot->meta.valid_from = 0;
    slot->meta.valid_until = SM2_PKI_WITNESS_KEY_VALID_UNTIL_OPEN;
    slot->meta.public_key = slot->public_key;
    return 1;
}

static int issue_identity(sm2_pki_service_ctx_t *service, const char *identity,
    uint8_t usage, uint64_t now_ts, sm2_ic_cert_result_t *cert,
    sm2_private_key_t *temp_private_key)
{
    sm2_ic_cert_request_t request;
    memset(&request, 0, sizeof(request));
    if (sm2_pki_identity_register(
            service, (const uint8_t *)identity, strlen(identity), usage)
        != SM2_PKI_SUCCESS)
        return 0;
    if (sm2_ic_create_cert_request(&request, (const uint8_t *)identity,
            strlen(identity), usage, temp_private_key)
        != SM2_IC_SUCCESS)
        return 0;
    if (sm2_pki_cert_authorize_request(service, &request) != SM2_PKI_SUCCESS)
        return 0;
    return sm2_pki_cert_issue(service, &request, now_ts, cert)
        == SM2_PKI_SUCCESS;
}

static int bind_policy(sm2_pki_service_ctx_t *service,
    const sm2_pki_transparency_policy_t *policy, uint64_t now_ts)
{
    uint8_t witness_digest[SM2_PKI_POLICY_DIGEST_LEN];
    uint8_t sync_digest[SM2_PKI_POLICY_DIGEST_LEN];
    if (sm2_pki_transparency_policy_digest(policy, witness_digest)
            != SM2_IC_SUCCESS
        || sm2_pki_default_sync_policy_digest(sync_digest) != SM2_IC_SUCCESS)
        return 0;
    return sm2_pki_service_set_epoch_policy_binding(service,
               SM2_PKI_DEFAULT_WITNESS_POLICY_VERSION, witness_digest,
               SM2_PKI_DEFAULT_SYNC_POLICY_VERSION, sync_digest, now_ts)
        == SM2_PKI_SUCCESS;
}

static int build_checkpoint(sm2_pki_service_ctx_t *service,
    const sm2_ec_point_t *ca_public_key,
    const sm2_pki_transparency_policy_t *policy, witness_slot_t *witnesses,
    size_t witness_count, uint64_t now_ts,
    sm2_pki_epoch_checkpoint_t *checkpoint)
{
    if (!bind_policy(service, policy, now_ts))
        return 0;
    memset(checkpoint, 0, sizeof(*checkpoint));
    if (sm2_pki_service_get_epoch_root_record(
            service, &checkpoint->epoch_root_record)
        != SM2_PKI_SUCCESS)
        return 0;

    size_t commitment_count = 0;
    if (sm2_pki_service_get_issuance_commitment_count(
            service, &commitment_count)
        != SM2_PKI_SUCCESS
        || commitment_count > 16U)
        return 0;
    sm2_pki_issuance_commitment_t commitments[16];
    memset(commitments, 0, sizeof(commitments));
    size_t exported_count = 0;
    if (commitment_count > 0U
        && (sm2_pki_service_export_issuance_commitments(service, 0, commitments,
                commitment_count, &exported_count)
                != SM2_PKI_SUCCESS
            || exported_count != commitment_count))
        return 0;

    for (size_t i = 0; i < witness_count; i++)
    {
        sm2_pki_epoch_witness_state_t state;
        sm2_pki_epoch_witness_state_init(&state);
        sm2_pki_error_t ret = sm2_pki_epoch_witness_sign_append_only(&state,
            &checkpoint->epoch_root_record, ca_public_key, now_ts, commitments,
            commitment_count, witnesses[i].meta.witness_id,
            witnesses[i].meta.witness_id_len, &witnesses[i].private_key,
            &checkpoint->witness_signatures[i]);
        sm2_pki_epoch_witness_state_cleanup(&state);
        if (ret != SM2_PKI_SUCCESS)
            return 0;
    }
    checkpoint->witness_signature_count = witness_count;
    return 1;
}

static int build_request(sm2_pki_client_ctx_t *client, const uint8_t *message,
    size_t message_len, uint64_t now_ts, sm2_auth_signature_t *signature,
    sm2_pki_evidence_bundle_t *evidence, sm2_pki_verify_request_t *request)
{
    const sm2_implicit_cert_t *cert = NULL;
    const sm2_ec_point_t *public_key = NULL;
    memset(signature, 0, sizeof(*signature));
    memset(evidence, 0, sizeof(*evidence));
    memset(request, 0, sizeof(*request));
    if (sm2_pki_sign(client, message, message_len, signature)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_export_epoch_evidence(client, now_ts, evidence)
            != SM2_PKI_SUCCESS
        || sm2_pki_client_get_cert(client, &cert) != SM2_PKI_SUCCESS
        || sm2_pki_client_get_public_key(client, &public_key)
            != SM2_PKI_SUCCESS)
        return 0;
    request->cert = cert;
    request->public_key = public_key;
    request->message = message;
    request->message_len = message_len;
    request->signature = signature;
    request->evidence_bundle = evidence;
    return 1;
}

int main(int argc, char **argv)
{
    app_config_t cfg;
    const char *config_path = "config/gateway.conf";
    const uint64_t base_now = 1760000100ULL;
    const uint8_t issuer[] = "EdgeAccessPKI-Industrial-CA";
    const uint8_t usage = SM2_KU_DIGITAL_SIGNATURE;

    app_config_default(&cfg);
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            config_path = argv[++i];
        else if (strcmp(argv[i], "--json") == 0)
            cfg.json_output = 1;
        else if (strcmp(argv[i], "--version") == 0)
        {
            printf("%s\n", APP_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else
        {
            print_usage(argv[0]);
            return 1;
        }
    }
    APP_CHECK(load_config(config_path, &cfg), "load gateway configuration");
    APP_CHECK(cfg.required_witnesses == 2U, "enforce 2-of-2 plant policy");
    printf("[INFO] site=%s line=%s terminal=%s controller=%s\n", cfg.site_id,
        cfg.line_id, cfg.terminal_id, cfg.controller_id);

    sm2_pki_service_ctx_t *service = NULL;
    APP_CHECK(sm2_pki_service_create(&service, issuer, sizeof(issuer) - 1, 64,
                  300, base_now)
            == SM2_PKI_SUCCESS,
        "create industrial CA service");

    sm2_ic_cert_result_t maint_cert;
    sm2_ic_cert_result_t controller_cert;
    sm2_private_key_t maint_temp;
    sm2_private_key_t controller_temp;
    memset(&maint_cert, 0, sizeof(maint_cert));
    memset(&controller_cert, 0, sizeof(controller_cert));
    memset(&maint_temp, 0, sizeof(maint_temp));
    memset(&controller_temp, 0, sizeof(controller_temp));
    APP_CHECK(issue_identity(service, cfg.terminal_id, usage, base_now + 1U,
                  &maint_cert, &maint_temp),
        "issue maintenance terminal certificate");
    APP_CHECK(issue_identity(service, cfg.controller_id, usage, base_now + 2U,
                  &controller_cert, &controller_temp),
        "issue line controller certificate");

    sm2_ec_point_t ca_public_key;
    APP_CHECK(sm2_pki_service_get_ca_public_key(service, &ca_public_key)
            == SM2_PKI_SUCCESS,
        "read industrial CA public key");

    witness_slot_t witnesses[2];
    APP_CHECK(init_witness(&witnesses[0], "plant-edge-w1"),
        "prepare witness plant-edge-w1");
    APP_CHECK(init_witness(&witnesses[1], "plant-edge-w2"),
        "prepare witness plant-edge-w2");
    sm2_pki_transparency_witness_t witness_meta[2]
        = { witnesses[0].meta, witnesses[1].meta };
    sm2_pki_transparency_policy_t policy = { witness_meta, 2U, 2U };

    sm2_pki_client_ctx_t *terminal = NULL;
    sm2_pki_client_ctx_t *gateway = NULL;
    APP_CHECK(sm2_pki_client_create(&terminal, &ca_public_key, service)
            == SM2_PKI_SUCCESS,
        "create maintenance terminal context");
    APP_CHECK(sm2_pki_client_create(&gateway, &ca_public_key, NULL)
            == SM2_PKI_SUCCESS,
        "create edge gateway verifier");
    APP_CHECK(sm2_pki_client_set_transparency_policy(gateway, &policy)
            == SM2_PKI_SUCCESS,
        "configure 2-of-2 witness policy");
    APP_CHECK(sm2_pki_client_import_cert(
                  terminal, &maint_cert, &maint_temp, &ca_public_key)
            == SM2_PKI_SUCCESS,
        "import maintenance terminal identity");

    sm2_pki_epoch_checkpoint_t checkpoint;
    APP_CHECK(build_checkpoint(service, &ca_public_key, &policy, witnesses, 2U,
                  base_now + 10U, &checkpoint),
        "build 2-of-2 checkpoint");
    APP_CHECK(sm2_pki_client_import_epoch_checkpoint(
                  gateway, &checkpoint, base_now + 10U)
            == SM2_PKI_SUCCESS,
        "import 2-of-2 checkpoint");

    const uint8_t *command = (const uint8_t *)cfg.command;
    const size_t command_len = strlen(cfg.command);
    sm2_auth_signature_t signature;
    sm2_pki_evidence_bundle_t evidence;
    sm2_pki_verify_request_t request;
    APP_CHECK(build_request(terminal, command, command_len, base_now + 10U,
                  &signature, &evidence, &request),
        "build signed maintenance command");

    size_t matched = 0;
    APP_CHECK(sm2_pki_verify(gateway, &request, base_now + 10U, &matched)
            == SM2_PKI_SUCCESS,
        "accept signed maintenance command");

    uint8_t wire[32768];
    size_t wire_len = sizeof(wire);
    APP_CHECK(sm2_pki_evidence_bundle_encode(&evidence, wire, &wire_len)
            == SM2_PKI_SUCCESS,
        "encode portable evidence");

    APP_CHECK(sm2_pki_service_revoke(
                  service, maint_cert.cert.serial_number, base_now + 20U)
            == SM2_PKI_SUCCESS,
        "revoke maintenance terminal");
    sm2_pki_epoch_checkpoint_t post_revoke_checkpoint;
    APP_CHECK(build_checkpoint(service, &ca_public_key, &policy, witnesses, 2U,
                  base_now + 20U, &post_revoke_checkpoint),
        "build post-revocation checkpoint");
    APP_CHECK(sm2_pki_client_import_epoch_checkpoint(
                  gateway, &post_revoke_checkpoint, base_now + 20U)
            == SM2_PKI_SUCCESS,
        "import post-revocation checkpoint");
    APP_CHECK(sm2_pki_verify(gateway, &request, base_now + 20U, &matched)
            == SM2_PKI_ERR_VERIFY,
        "reject command after revocation");

    if (cfg.json_output)
    {
        printf("{\"product\":\"EdgeAccessPKI\",\"site\":\"%s\","
               "\"line\":\"%s\",\"terminal\":\"%s\","
               "\"decision_before_revocation\":\"ALLOW\","
               "\"decision_after_revocation\":\"DENY\","
               "\"required_witnesses\":%u,\"fail_closed\":%s}\n",
            cfg.site_id, cfg.line_id, cfg.terminal_id, cfg.required_witnesses,
            cfg.fail_closed ? "true" : "false");
    }
    else
    {
        printf("[DECISION] ALLOW maintenance command before revocation\n");
        printf("[DECISION] DENY maintenance command after revocation\n");
    }

    sm2_pki_client_destroy(&gateway);
    sm2_pki_client_destroy(&terminal);
    sm2_pki_service_destroy(&service);
    return 0;
}
