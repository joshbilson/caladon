import { hasPermissions } from 'librechat-data-provider/react-query';
import { ResourceType } from 'librechat-data-provider';

/**
 * Caladon overlay — trust-no-one resource permissions.
 *
 * Upstream this hook calls a server endpoint (`useGetEffectivePermissionsQuery`) to learn what the
 * current user may do with a shared resource. In Caladon there is no server-side resource registry:
 * agents, prompts/skills, and MCP servers all live ONLY in the encrypted device store and are owned
 * outright by the local identity. So the local user always has full owner rights (VIEW|EDIT|DELETE)
 * over their own device-local resources — there is nobody else to grant access to.
 *
 * We deliberately do NOT grant SHARE: sharing a resource off-device would mean handing plaintext to
 * a server, which contradicts the device-only trust model. The share UI stays hidden.
 *
 * This keeps the builder editable (upstream gates the Agent/Prompt/MCP editors on EDIT) without ever
 * round-tripping a permission check to the gateway.
 */
const VIEW = 1;
const EDIT = 2;
const DELETE = 4;
const OWNER_BITS = VIEW | EDIT | DELETE; // 7 — no SHARE (off-device sharing is disabled)

const DEVICE_LOCAL_RESOURCES = new Set<ResourceType>([
  ResourceType.AGENT,
  ResourceType.PROMPTGROUP,
]);

export const useResourcePermissions = (resourceType: ResourceType, _resourceId: string) => {
  const isDeviceLocal = DEVICE_LOCAL_RESOURCES.has(resourceType);
  const bits = isDeviceLocal ? OWNER_BITS : 0;

  const hasPermission = (requiredPermission: number): boolean => {
    if (isDeviceLocal) {
      return hasPermissions(bits, requiredPermission);
    }
    return false;
  };

  return {
    hasPermission,
    isLoading: false,
    permissionBits: bits,
  };
};

export default useResourcePermissions;
