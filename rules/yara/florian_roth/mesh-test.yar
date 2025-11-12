rule Mesh_Agent_Strings
{
    meta:
        description = "Detects Mesh Agent related strings"
        author = "Your Name"
        date = "2024-01-01"
        severity = "High"
    
    strings:
        $s1 = "MeshServer" ascii wide
        $s2 = "example-mesh-agent.com" ascii wide
        $s3 = "MeshID" ascii wide
    
    condition:
        any of them
}