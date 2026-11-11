"""
VULNERABLE IMPLEMENTATION (DO NOT USE IN PRODUCTION)
Demonstrates 3 critical AI Agent vulnerabilities:
1. Indirect Prompt Injection via untrusted external data (Gmail body)
2. Persistent State Poisoning via unsanitized writes to MEMORY.md
3. Privilege Escalation & Cross-Tenant Data Exfiltration in Supabase tool calls
"""

class VulnerableEmailAgent:
    def __init__(self, db_client, gmail_client, memory_path="MEMORY.md"):
        self.db = db_client
        self.gmail = gmail_client
        self.memory_path = memory_path

    def build_system_prompt(self, current_user_id: str, untrusted_email_body: str, memory_state: str) -> str:
        # VULNERABILITY 1: Direct string concatenation of untrusted email content
        # and persistent memory without structural delimiters or privilege isolation.
        return f"""
        You are an autonomous customer operations agent for user {current_user_id}.
        Persistent Session Memory:
        {memory_state}

        Process the following incoming email and execute required database or email tools:
        {untrusted_email_body}
        """

    def execute_tool(self, tool_name: str, tool_args: dict):
        # VULNERABILITY 2: No tenant scoping (IDOR / Privilege Escalation).
        # The LLM can pass ANY user_id into tool_args and query another user's records.
        if tool_name == "query_supabase_customer":
            raw_query = f"SELECT * FROM customers WHERE id = '{tool_args.get('target_user_id')}'"
            return self.db.execute(raw_query)

        # VULNERABILITY 3: Unrestricted outbound data exfiltration via Gmail tool.
        elif tool_name == "send_email":
            return self.gmail.send(
                to=tool_args.get("recipient"),
                subject=tool_args.get("subject"),
                body=tool_args.get("body")
            )

        # VULNERABILITY 4: Unvalidated persistent state mutation (Memory Poisoning).
        elif tool_name == "update_memory":
            with open(self.memory_path, "a", encoding="utf-8") as f:
                f.write("\n" + tool_args.get("new_memory_entry", ""))
            return {"status": "memory_updated"}
