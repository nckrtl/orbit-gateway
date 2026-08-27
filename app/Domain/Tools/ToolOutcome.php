<?php

declare(strict_types=1);

namespace App\Domain\Tools;

enum ToolOutcome: string
{
    case Applied = 'applied';
    case Unchanged = 'unchanged';
    case BlockedByConstraint = 'blocked_by_constraint';
    case ConstraintInvalid = 'constraint_invalid';
    case CandidateVersionUnavailable = 'candidate_version_unavailable';
    case CandidateVersionUnparseable = 'candidate_version_unparseable';
    case ManagerFailed = 'manager_failed';
}
