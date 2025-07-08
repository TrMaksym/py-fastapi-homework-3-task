from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone

from database.models.accounts import UserModel, ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
)
from database.session_postgresql import get_postgresql_db as get_db
from src.security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManagerInterface
from config.dependencies import get_jwt_auth_manager
from schemas.accounts import UserGroupEnum

router = APIRouter()

@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == user_data.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    try:
        hashed_password = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            hashed_password=hashed_password,
            is_active=False,
            group=UserGroupEnum.USER,
        )
        db.add(new_user)
        await db.flush()

        await ActivationTokenModel.create(db, user_id=new_user.id)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return {
        "id": new_user.id,
        "email": new_user.email,
    }

@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ActivationTokenModel)
        .filter(
            ActivationTokenModel.token == activation_data.token,
            ActivationTokenModel.user.has(email=activation_data.email),
        )
    )
    token_record = result.scalars().first()

    if not token_record or token_record.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user activation.",
        )

    return {"message": "User account activated successfully."}

@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).filter(UserModel.email == data.email, UserModel.is_active == True)
    )
    user = result.scalars().first()

    if user:
        await db.execute(
            PasswordResetTokenModel.__table__.delete().where(PasswordResetTokenModel.user_id == user.id)
        )
        await PasswordResetTokenModel.create(db, user_id=user.id)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}

@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.token == data.token)
        .join(UserModel)
        .filter(UserModel.email == data.email, UserModel.is_active == True)
    )
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record or token_record.is_expired():
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    user = token_record.user
    try:
        user.hashed_password = hash_password(data.password)
        await db.delete(token_record)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return {"message": "Password reset successfully."}

@router.post("/login/", status_code=status.HTTP_200_OK)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == login_data.email))
    user = result.scalars().first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    try:
        refresh_token = jwt_manager.create_refresh_token(subject=str(user.id))
        await RefreshTokenModel.create(db, user_id=user.id, token=refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    access_token = jwt_manager.create_access_token(subject=str(user.id))
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    result = await db.execute(select(RefreshTokenModel).filter(RefreshTokenModel.token == token_data.refresh_token))
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    result = await db.execute(select(UserModel).filter(UserModel.id == payload.get("sub")))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    new_access_token = jwt_manager.create_access_token(subject=str(user.id))
    return {"access_token": new_access_token}
